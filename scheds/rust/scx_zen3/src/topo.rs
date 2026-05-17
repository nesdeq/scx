// SPDX-License-Identifier: GPL-2.0
//
// Topology probe for scx_zen3. Reads sysfs to determine:
//   - CCD count and CCD membership per CPU.
//   - SMT siblings.
//   - amd_pstate_prefcore_ranking per CPU; falls back to cpuinfo_max_freq
//     and then to physical CPU order.
//   - X3D detection from L3 cache size.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::bpf_intf::zen3_consts_MAX_CCDS as MAX_CCDS;
use crate::bpf_intf::zen3_consts_MAX_CORES_PER_CCD as MAX_CORES_PER_CCD;
use crate::bpf_intf::zen3_consts_MAX_CPUS as MAX_CPUS;

#[derive(Debug, Clone)]
pub struct CcdInfo {
    pub id: u32,
    /// CPU IDs sorted by descending prefcore rank (rank 0 = best at index 0).
    pub cpus_by_rank: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Topo {
    pub nr_cpu_ids: u32,
    pub nr_ccds: u32,
    pub is_x3d: bool,
    pub smt_enabled: bool,
    pub ccds: Vec<CcdInfo>,
    /// cpu_to_ccd[cpu] = ccd_id
    pub cpu_to_ccd: Vec<u32>,
    /// CCD ID with the highest-ranked prefcore (== auto game CCD).
    /// Cached at probe time so hot stats paths don't re-sysfs-read.
    pub default_game_ccd: i32,
}

impl Topo {
    pub fn probe() -> Result<Self> {
        let nr_cpu_ids = read_nr_cpu_ids()?;
        if (nr_cpu_ids as usize) > MAX_CPUS as usize {
            return Err(anyhow!(
                "nr_cpu_ids={} exceeds compile-time MAX_CPUS={}",
                nr_cpu_ids,
                MAX_CPUS
            ));
        }

        let smt_enabled = (0..nr_cpu_ids).any(has_smt_sibling);

        // Group CPUs by L3-shared (= CCX = CCD on Zen 3).
        let mut l3_groups: Vec<Vec<u32>> = Vec::new();
        let mut cpu_to_ccd = vec![u32::MAX; nr_cpu_ids as usize];

        let mut max_l3_kb = 0u64;
        for cpu in 0..nr_cpu_ids {
            if cpu_to_ccd[cpu as usize] != u32::MAX {
                continue;
            }
            let (members, l3_kb) = read_l3_group(cpu)?;
            if l3_kb > max_l3_kb {
                max_l3_kb = l3_kb;
            }
            let ccd_id = l3_groups.len() as u32;
            for m in &members {
                if (*m as usize) < cpu_to_ccd.len() {
                    cpu_to_ccd[*m as usize] = ccd_id;
                }
            }
            l3_groups.push(members);
        }

        let nr_ccds = l3_groups.len() as u32;
        if nr_ccds as usize > MAX_CCDS as usize {
            return Err(anyhow!(
                "nr_ccds={} exceeds compile-time MAX_CCDS={}",
                nr_ccds,
                MAX_CCDS
            ));
        }

        // L3 > 64 MiB → 3D V-Cache (5800X3D).
        let is_x3d = max_l3_kb > 64 * 1024;

        // Sort each CCD's CPU list by prefcore rank descending.
        let mut ccds = Vec::with_capacity(nr_ccds as usize);
        for (id, members) in l3_groups.into_iter().enumerate() {
            // (rank_value, cpu_id). Higher prefcore = "faster"; sort
            // descending so rank 0 = best.
            let mut keyed: Vec<(u32, u32)> = members
                .into_iter()
                .map(|cpu| (read_prefcore_or_freq(cpu).unwrap_or(0), cpu))
                .collect();
            keyed.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let members: Vec<u32> = keyed.into_iter().map(|(_, c)| c).collect();

            if members.len() > MAX_CORES_PER_CCD as usize {
                return Err(anyhow!(
                    "CCD {} has {} CPUs > MAX_CORES_PER_CCD={}",
                    id,
                    members.len(),
                    MAX_CORES_PER_CCD
                ));
            }

            ccds.push(CcdInfo {
                id: id as u32,
                cpus_by_rank: members,
            });
        }

        let default_game_ccd = compute_default_game_ccd(&ccds);

        Ok(Topo {
            nr_cpu_ids,
            nr_ccds,
            is_x3d,
            smt_enabled,
            ccds,
            cpu_to_ccd,
            default_game_ccd,
        })
    }
}

fn compute_default_game_ccd(ccds: &[CcdInfo]) -> i32 {
    // Highest single prefcore among CCDs wins.
    let mut best: (i32, u32) = (-1, 0);
    for ccd in ccds {
        if let Some(&cpu0) = ccd.cpus_by_rank.first() {
            if let Some(v) = read_prefcore_or_freq(cpu0) {
                if v > best.1 {
                    best = (ccd.id as i32, v);
                }
            }
        }
    }
    if best.0 < 0 && !ccds.is_empty() {
        0
    } else {
        best.0
    }
}

fn read_nr_cpu_ids() -> Result<u32> {
    // online cpus is the safest single source; nr_cpu_ids would be possible
    // but we only schedule online ones anyway.
    let p = "/sys/devices/system/cpu/online";
    let s = fs::read_to_string(p).context("read /sys/.../cpu/online")?;
    let s = s.trim();
    let mut max_cpu: i64 = -1;
    for part in s.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let b: i64 = b.trim().parse()?;
            if b > max_cpu {
                max_cpu = b;
            }
            let a: i64 = a.trim().parse()?;
            if a > max_cpu {
                max_cpu = a;
            }
        } else {
            let n: i64 = part.trim().parse()?;
            if n > max_cpu {
                max_cpu = n;
            }
        }
    }
    if max_cpu < 0 {
        Err(anyhow!("no online CPUs detected"))
    } else {
        Ok((max_cpu + 1) as u32)
    }
}

/// True if @cpu has any SMT sibling other than itself.
fn has_smt_sibling(cpu: u32) -> bool {
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/topology/thread_siblings_list",
        cpu
    );
    let Ok(s) = fs::read_to_string(&path) else {
        return false;
    };
    s.trim().split(',').any(|part| {
        if let Some((a, b)) = part.split_once('-') {
            let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) else {
                return false;
            };
            (a..=b).any(|v| v != cpu)
        } else {
            part.trim().parse::<u32>().map(|v| v != cpu).unwrap_or(false)
        }
    })
}

/// Returns (cpu_members, l3_size_kb).
fn read_l3_group(cpu: u32) -> Result<(Vec<u32>, u64)> {
    let cache_root = format!("/sys/devices/system/cpu/cpu{}/cache", cpu);
    for idx in 0..8u32 {
        let dir = format!("{}/index{}", cache_root, idx);
        if !Path::new(&dir).exists() {
            continue;
        }
        let level: u32 = fs::read_to_string(format!("{}/level", dir))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if level != 3 {
            continue;
        }
        let shared = fs::read_to_string(format!("{}/shared_cpu_list", dir))
            .context("read shared_cpu_list")?;
        let size_str = fs::read_to_string(format!("{}/size", dir))
            .unwrap_or_else(|_| String::from("0K"));
        let size_kb = parse_size_kb(size_str.trim()).unwrap_or(0);

        let mut members = Vec::new();
        for part in shared.trim().split(',') {
            if let Some((a, b)) = part.split_once('-') {
                let a: u32 = a.trim().parse()?;
                let b: u32 = b.trim().parse()?;
                for v in a..=b {
                    members.push(v);
                }
            } else {
                let v: u32 = part.trim().parse()?;
                members.push(v);
            }
        }
        members.sort();
        members.dedup();
        return Ok((members, size_kb));
    }
    // No L3 found; degenerate to "this CPU alone".
    Ok((vec![cpu], 0))
}

fn parse_size_kb(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('K') {
        num.trim().parse::<u64>().ok()
    } else if let Some(num) = s.strip_suffix('M') {
        num.trim().parse::<u64>().ok().map(|n| n * 1024)
    } else if let Some(num) = s.strip_suffix('G') {
        num.trim().parse::<u64>().ok().map(|n| n * 1024 * 1024)
    } else {
        s.parse::<u64>().ok().map(|n| n / 1024)
    }
}

/// Returns a rank value for a CPU. Larger = better. Tries:
///   1. amd_pstate_prefcore_ranking
///   2. cpuinfo_max_freq
///   3. 1 (constant, degrades the ranking to physical order)
fn read_prefcore_or_freq(cpu: u32) -> Option<u32> {
    let prefcore = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/amd_pstate_prefcore_ranking",
        cpu
    );
    if let Ok(s) = fs::read_to_string(&prefcore) {
        if let Ok(n) = s.trim().parse::<u32>() {
            return Some(n);
        }
    }
    let max_freq = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/cpuinfo_max_freq",
        cpu
    );
    if let Ok(s) = fs::read_to_string(&max_freq) {
        if let Ok(n) = s.trim().parse::<u32>() {
            // Use freq directly as rank.
            return Some(n);
        }
    }
    Some(1)
}
