// SPDX-License-Identifier: GPL-2.0
//
// Game-family / audio / compositor / anti-cheat detection by walking
// /proc. Runs in userspace on a 250 ms timer; writes results into the
// BPF side via syscall programs.
//
// Detection priorities (cake-style):
//   1. Steam env var (`SteamGameId=` or `STEAM_GAME=`) — conf 100, instant.
//   2. Wine/Proton `.exe` in cmdline — conf 90, 5 s holdoff (must persist).
//
// Audio: known daemon `comm` names.
// Compositor: known Wayland/X11 compositor `comm` names.
// Anti-cheat: known service binary names.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

const AUDIO_NAMES: &[&str] = &[
    "pipewire",
    "wireplumber",
    "pipewire-pulse",
    "pulseaudio",
    "jackd",
    "jackdbus",
];

const COMPOSITOR_NAMES: &[&str] = &[
    "kwin_wayland",
    "kwin_x11",
    "mutter",
    "gnome-shell",
    "sway",
    "Hyprland",
    "weston",
    "labwc",
    "wayfire",
    "river",
    "gamescope",
    "hyprland",
    "kwin",
];

const ANTICHEAT_NAMES: &[&str] = &[
    "EasyAntiCheat",
    "EasyAntiCheat_x64",
    "BEService",
    "BEService_x64",
    "vgc",
    "vgk",
    "eos-anticheat",
    "anticheat",
];

#[derive(Debug, Default, Clone)]
pub struct Detection {
    /// PID of the detected game's top-level process (TGID).
    pub game_tgid: Option<i32>,
    /// Confidence: 100 (Steam env), 90 (Wine .exe), 0 (no game).
    pub game_confidence: u32,
    /// Process name of the game (for display).
    pub game_name: Option<String>,
    /// All PIDs (TIDs) belonging to the game family, mapped to role bits.
    pub family: HashMap<i32, u32>,
    /// Anti-cheat PIDs.
    pub anticheat: HashSet<i32>,
}

#[derive(Debug, Default)]
pub struct DetectState {
    pub last_detection: Detection,
    /// PIDs we're considering for a Wine .exe lock; (pid, first_seen).
    wine_candidate: Option<(i32, Instant)>,
}

const ROLE_FAMILY: u32 = 1 << 0;
const ROLE_AUDIO: u32 = 1 << 1;
const ROLE_COMPOSITOR: u32 = 1 << 2;
const WINE_HOLDOFF: Duration = Duration::from_secs(5);

impl DetectState {
    pub fn scan(&mut self) -> Detection {
        let procs = list_pids();
        let mut detection = Detection::default();

        // 1. Walk /proc once, collecting comm / cmdline / env hints.
        let mut steam_game: Option<(i32, String)> = None;
        let mut wine_game: Option<(i32, String)> = None;

        for &pid in &procs {
            let Some(comm) = read_comm(pid) else { continue };
            if comm.is_empty() {
                continue;
            }
            let tgid = read_tgid(pid).unwrap_or(pid);

            // Anti-cheat: simple comm match. Per-thread granularity OK.
            if ANTICHEAT_NAMES
                .iter()
                .any(|n| comm.eq_ignore_ascii_case(n) || comm.starts_with(n))
            {
                detection.anticheat.insert(pid);
            }

            // The remainder is per-process (TGID-level) classification.
            if pid != tgid {
                continue;
            }

            if AUDIO_NAMES.iter().any(|n| comm.eq_ignore_ascii_case(n)) {
                *detection.family.entry(pid).or_default() |= ROLE_AUDIO;
            }
            if COMPOSITOR_NAMES.iter().any(|n| comm.eq_ignore_ascii_case(n)) {
                *detection.family.entry(pid).or_default() |= ROLE_COMPOSITOR;
            }

            if steam_game.is_none() && has_steam_env(pid) {
                steam_game = Some((pid, comm.clone()));
            }
            if wine_game.is_none() && steam_game.is_none() {
                if let Some(exe) = wine_exe_name_from_cmdline(pid) {
                    wine_game = Some((pid, exe));
                }
            }
        }

        // 2. Choose the game (Steam wins; else Wine after holdoff).
        if let Some((tgid, name)) = steam_game {
            detection.game_tgid = Some(tgid);
            detection.game_confidence = 100;
            detection.game_name = Some(name);
            self.wine_candidate = None;
        } else if let Some((tgid, name)) = wine_game {
            let now = Instant::now();
            let locked = matches!(self.wine_candidate, Some((p, t))
                if p == tgid && now.duration_since(t) >= WINE_HOLDOFF);
            if !locked && self.wine_candidate.map(|(p, _)| p) != Some(tgid) {
                self.wine_candidate = Some((tgid, now));
            }
            if locked {
                detection.game_tgid = Some(tgid);
                detection.game_confidence = 90;
                detection.game_name = Some(name);
            }
        } else {
            self.wine_candidate = None;
        }

        // Stickiness: if previous detection's game tgid still exists, keep it.
        // Only replace if new detection has strictly higher confidence.
        if let Some(prev_tgid) = self.last_detection.game_tgid {
            let prev_alive = procs.binary_search(&prev_tgid).is_ok();
            if prev_alive {
                let new_conf = detection.game_confidence;
                if new_conf < self.last_detection.game_confidence {
                    detection.game_tgid = Some(prev_tgid);
                    detection.game_confidence = self.last_detection.game_confidence;
                    detection.game_name = self.last_detection.game_name.clone();
                }
            }
        }

        // 3. If a game is locked in, build its family by collecting all PIDs
        //    whose parent chain hits the game tgid (or matches a child PID).
        if let Some(game_tgid) = detection.game_tgid {
            let mut family_tgids: HashSet<i32> = HashSet::new();
            family_tgids.insert(game_tgid);

            let parent_of: HashMap<i32, i32> = procs
                .iter()
                .filter_map(|&pid| {
                    let parent = read_ppid(pid)?;
                    Some((pid, parent))
                })
                .collect();

            // BFS down from game_tgid into the parent_of inverse map.
            // Build child map first.
            let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
            for (&child, &parent) in &parent_of {
                children.entry(parent).or_default().push(child);
            }
            let mut frontier = vec![game_tgid];
            while let Some(p) = frontier.pop() {
                if let Some(kids) = children.get(&p) {
                    for &k in kids {
                        if family_tgids.insert(k) {
                            frontier.push(k);
                        }
                    }
                }
            }

            // Also include every thread of every family tgid.
            for tgid in family_tgids.iter().copied().collect::<Vec<_>>() {
                for tid in list_threads(tgid) {
                    detection
                        .family
                        .entry(tid)
                        .and_modify(|v| *v |= ROLE_FAMILY)
                        .or_insert(ROLE_FAMILY);
                }
            }
        }

        self.last_detection = detection.clone();
        detection
    }

    pub fn is_gaming(&self) -> bool {
        self.last_detection.game_tgid.is_some() && self.last_detection.game_confidence >= 90
    }
}

fn list_pids() -> Vec<i32> {
    let mut out = Vec::with_capacity(512);
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<i32>() {
                out.push(pid);
            }
        }
    }
    out.sort();
    out
}

fn list_threads(tgid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let path = format!("/proc/{}/task", tgid);
    let Ok(entries) = fs::read_dir(&path) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(tid) = name.parse::<i32>() {
                out.push(tid);
            }
        }
    }
    out
}

fn read_comm(pid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    Some(s.trim().to_string())
}

fn read_tgid(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn read_ppid(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn has_steam_env(pid: i32) -> bool {
    let p = format!("/proc/{}/environ", pid);
    let Ok(bytes) = fs::read(&p) else {
        return false;
    };
    for chunk in bytes.split(|&b| b == 0) {
        let Ok(s) = std::str::from_utf8(chunk) else {
            continue;
        };
        if s.starts_with("SteamGameId=") && !s.ends_with("=") && s.len() > 12 {
            return true;
        }
        if s.starts_with("STEAM_GAME=") && !s.ends_with("=") && s.len() > 11 {
            return true;
        }
    }
    false
}

fn wine_exe_name_from_cmdline(pid: i32) -> Option<String> {
    let p = format!("/proc/{}/cmdline", pid);
    let bytes = fs::read(&p).ok()?;
    for chunk in bytes.split(|&b| b == 0) {
        let Ok(s) = std::str::from_utf8(chunk) else {
            continue;
        };
        // Heuristic: an arg ending in `.exe` and containing no Windows infra name.
        let lower = s.to_ascii_lowercase();
        if !lower.ends_with(".exe") {
            continue;
        }
        // Skip infrastructure exes.
        let basename = lower
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(lower.as_str());
        let blocked = [
            "services.exe",
            "winedevice.exe",
            "pluginhost.exe",
            "svchost.exe",
            "explorer.exe",
            "wineboot.exe",
            "crashhandler.exe",
            "rundll32.exe",
            "conhost.exe",
            "cmd.exe",
            "winecfg.exe",
            "pressure-vessel.exe",
        ];
        if blocked.contains(&basename) {
            continue;
        }
        return Some(basename.to_string());
    }
    None
}
