// SPDX-License-Identifier: GPL-2.0
//
// scx_zen3 — Zen 3-specific sched_ext scheduler.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod detect;
mod stats;
mod topo;

use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

use detect::DetectState;
use stats::Metrics;
use topo::Topo;

const SCHEDULER_NAME: &str = "scx_zen3";

/// Drive a SEC("syscall") BPF program with a typed args struct.
///
/// Wraps the prog.test_run() boilerplate (build a ProgramInput, point its
/// context_in at the args, invoke, return the program's return value).
/// Implemented as a macro because libbpf-rs's typed accessors return
/// distinct ProgramImpl instances rather than &mut Program.
macro_rules! run_syscall_prog {
    ($prog:expr, $args:expr) => {{
        let args_ptr = $args as *mut _ as *mut u8;
        let args_size = std::mem::size_of_val::<_>($args);
        let input = ProgramInput {
            context_in: Some(unsafe { std::slice::from_raw_parts_mut(args_ptr, args_size) }),
            ..Default::default()
        };
        $prog
            .test_run(input)
            .map(|out| out.return_value)
            .map_err(anyhow::Error::from)
    }};
}

#[derive(Debug, Parser, Clone)]
#[command(
    name = "scx_zen3",
    version,
    disable_version_flag = true,
    about = "Zen 3-specific sched_ext scheduler optimised for gaming latency on AM4 Ryzen 5000 desktops.",
    long_about = r#"
scx_zen3 is a sched_ext scheduler purpose-built for AMD Zen 3 desktop CPUs (Vermeer/Cezanne).

In GAMING mode (auto-detected from Steam env vars or Wine .exe processes), it:
  * Reserves the firmware-ranked top cores of a single CCD for the game's render/sim pipeline.
  * Sends background CPU-bound work to the other CCD (or to the slow end of a single CCD).
  * Uses VPROT-style preemption to protect render threads from non-game work.
  * Applies cache-warm stickiness to vsync wakeups (100 ms L3 window).
  * Caps HOG-class CPU usage on the game CCD to 25%.
  * Auto-detects 5800X3D (L3 > 64 MiB) and disables CPUPERF nudging.

In IDLE mode (no game detected), it behaves like a Flash-style EDF scheduler with per-CCD DSQs.
"#
)]
struct Opts {
    /// Util_avg-style threshold (0-1024) above which non-family tasks become HOG.
    #[clap(long, default_value = "800")]
    hog_threshold_x1024: u32,

    /// Force a specific CCD as the game CCD; -1 = auto from prefcore ranking.
    #[clap(long, default_value = "-1", allow_hyphen_values = true)]
    game_ccd: i32,

    /// Disable scx_bpf_cpuperf_set nudging (recommended on 5800X3D — auto-detected).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_cpufreq: bool,

    /// Disable SMT avoidance for GAME_RENDER (will allow sibling pairing).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_smt_avoid: bool,

    /// Render-class default slice in microseconds.
    #[clap(long, default_value = "1500")]
    slice_render_us: u64,

    /// Build-class default slice in microseconds.
    #[clap(long, default_value = "2000")]
    slice_build_us: u64,

    /// Normal-class default slice in microseconds.
    #[clap(long, default_value = "2000")]
    slice_normal_us: u64,

    /// Hog-class default slice in microseconds.
    #[clap(long, default_value = "4000")]
    slice_hog_us: u64,

    /// BG-class default slice in microseconds.
    #[clap(long, default_value = "4000")]
    slice_bg_us: u64,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Enable verbose logging (libbpf debug, tracefs).
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Periodic stats output interval (seconds).
    #[clap(long)]
    stats: Option<f64>,

    /// Monitor a running scx_zen3 (do not load).
    #[clap(long)]
    monitor: Option<f64>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    topo: Topo,
    opts: Opts,
    detect: DetectState,
    last_family: HashMap<i32, u32>,
    last_anticheat: HashSet<i32>,
    is_gaming: bool,
    game_tgid: i32,
}

impl<'a> Scheduler<'a> {
    fn init(opts: Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let topo = Topo::probe().context("topology probe failed")?;
        info!(
            "{} {} | cpus={} ccds={} x3d={} smt={}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            topo.nr_cpu_ids,
            topo.nr_ccds,
            topo.is_x3d,
            topo.smt_enabled,
        );
        for ccd in &topo.ccds {
            info!(
                "  CCD {}: cpus_by_rank = {:?}",
                ccd.id, ccd.cpus_by_rank
            );
        }

        // Open + apply rodata.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, zen3_ops, open_opts)?;

        skel.struct_ops.zen3_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata map missing — skeleton build issue?")?;

        rodata.nr_cpu_ids = topo.nr_cpu_ids;
        rodata.nr_ccds = topo.nr_ccds;
        rodata.is_x3d = if topo.is_x3d { 1 } else { 0 };
        rodata.enable_cpufreq = if opts.no_cpufreq || topo.is_x3d { 0 } else { 1 };
        rodata.smt_enabled = if topo.smt_enabled { 1 } else { 0 };
        rodata.enable_smt_avoidance = if opts.no_smt_avoid { 0 } else { 1 };

        rodata.slice_render_ns = opts.slice_render_us * 1_000;
        rodata.slice_build_ns = opts.slice_build_us * 1_000;
        rodata.slice_normal_ns = opts.slice_normal_us * 1_000;
        rodata.slice_hog_ns = opts.slice_hog_us * 1_000;
        rodata.slice_bg_ns = opts.slice_bg_us * 1_000;
        rodata.hog_threshold_x1024 = opts.hog_threshold_x1024;

        if topo.nr_ccds > 2 {
            warn!(
                "detected {} CCDs (Threadripper/EPYC?); scx_zen3 is tuned for AM4 Vermeer; \
                 anti-CCD heuristics fall back to round-robin",
                topo.nr_ccds
            );
        }

        // Topology arrays. The BPF side only needs cpu_to_ccd,
        // cpus_per_ccd, and prefcore_rank_to_cpu — SMT siblings and
        // per-CPU rank are recovered from cpu_to_ccd × the
        // prefcore_rank_to_cpu table when needed.
        for (cpu, &ccd) in topo.cpu_to_ccd.iter().enumerate() {
            if cpu < rodata.cpu_to_ccd.len() {
                rodata.cpu_to_ccd[cpu] = ccd;
            }
        }
        for ccd in &topo.ccds {
            if (ccd.id as usize) < rodata.cpus_per_ccd.len() {
                rodata.cpus_per_ccd[ccd.id as usize] = ccd.cpus_by_rank.len() as u32;
            }
            for (rank, &cpu) in ccd.cpus_by_rank.iter().enumerate() {
                if (ccd.id as usize) < rodata.prefcore_rank_to_cpu.len()
                    && rank < rodata.prefcore_rank_to_cpu[ccd.id as usize].len()
                {
                    rodata.prefcore_rank_to_cpu[ccd.id as usize][rank] = cpu;
                }
            }
        }

        // Load + attach.
        let mut skel = scx_ops_load!(skel, zen3_ops, uei)?;

        let initial_game_ccd: i32 = if opts.game_ccd >= 0 {
            opts.game_ccd
        } else {
            topo.default_game_ccd
        };

        // Set initial mode = IDLE.
        Self::syscall_set_state(&mut skel, false, initial_game_ccd)?;

        let struct_ops = Some(scx_ops_attach!(skel, zen3_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Scheduler {
            skel,
            struct_ops,
            stats_server,
            topo,
            opts,
            detect: DetectState::default(),
            last_family: HashMap::new(),
            last_anticheat: HashSet::new(),
            is_gaming: false,
            game_tgid: 0,
        })
    }

    fn syscall_set_state(
        skel: &mut BpfSkel<'_>,
        is_gaming: bool,
        game_ccd: i32,
    ) -> Result<()> {
        let mut args = zen3_config_arg {
            is_gaming: if is_gaming { 1 } else { 0 },
            game_ccd,
        };
        let rv = run_syscall_prog!(skel.progs.zen3_set_state, &mut args)?;
        if rv != 0 {
            warn!("zen3_set_state returned {}", rv as i32);
        }
        Ok(())
    }

    fn syscall_update_family(
        skel: &mut BpfSkel<'_>,
        pid: i32,
        role_bits: u32,
        add: bool,
    ) -> Result<()> {
        let mut args = zen3_family_arg {
            pid,
            role_bits,
            op: if add { 1 } else { 0 },
            pad0: 0,
        };
        let _ = run_syscall_prog!(skel.progs.zen3_update_family, &mut args)?;
        Ok(())
    }

    fn syscall_update_anticheat(
        skel: &mut BpfSkel<'_>,
        pid: i32,
        add: bool,
    ) -> Result<()> {
        let mut args = zen3_anticheat_arg {
            pid,
            op: if add { 1 } else { 0 },
        };
        let _ = run_syscall_prog!(skel.progs.zen3_update_anticheat, &mut args)?;
        Ok(())
    }

    fn push_detection(&mut self) -> Result<()> {
        let det = self.detect.scan();

        // Diff family map: remove PIDs that left, add/update those that arrived.
        let mut to_remove: Vec<i32> = Vec::new();
        for &pid in self.last_family.keys() {
            if !det.family.contains_key(&pid) {
                to_remove.push(pid);
            }
        }
        for pid in to_remove {
            let _ = Self::syscall_update_family(&mut self.skel, pid, 0, false);
            self.last_family.remove(&pid);
        }
        for (&pid, &role) in &det.family {
            match self.last_family.get(&pid) {
                Some(&prev) if prev == role => continue,
                _ => {
                    let _ = Self::syscall_update_family(&mut self.skel, pid, role, true);
                    self.last_family.insert(pid, role);
                }
            }
        }

        // Diff anti-cheat set.
        let mut to_remove: Vec<i32> = Vec::new();
        for &pid in &self.last_anticheat {
            if !det.anticheat.contains(&pid) {
                to_remove.push(pid);
            }
        }
        for pid in to_remove {
            let _ = Self::syscall_update_anticheat(&mut self.skel, pid, false);
            self.last_anticheat.remove(&pid);
        }
        for &pid in &det.anticheat {
            if !self.last_anticheat.contains(&pid) {
                let _ = Self::syscall_update_anticheat(&mut self.skel, pid, true);
                self.last_anticheat.insert(pid);
            }
        }

        let new_is_gaming = self.detect.is_gaming();
        let new_game_tgid = det.game_tgid.unwrap_or(0);

        if new_is_gaming != self.is_gaming || new_game_tgid != self.game_tgid {
            let game_ccd = if self.opts.game_ccd >= 0 {
                self.opts.game_ccd
            } else {
                self.topo.default_game_ccd
            };
            let _ = Self::syscall_set_state(&mut self.skel, new_is_gaming, game_ccd);
            if new_is_gaming && !self.is_gaming {
                info!(
                    "Entered GAMING mode: tgid={} name={:?} game_ccd={}",
                    new_game_tgid,
                    det.game_name.as_deref().unwrap_or(""),
                    game_ccd
                );
            } else if !new_is_gaming && self.is_gaming {
                info!("Exited GAMING mode");
            }
            self.is_gaming = new_is_gaming;
            self.game_tgid = new_game_tgid;
        }

        Ok(())
    }

    fn collect_metrics(&mut self) -> Metrics {
        // Aggregate per-CPU stats[NR_ZEN3_STATS] by reading the BPF map.
        const NR: usize = zen3_stat_idx_NR_ZEN3_STATS as usize;
        let mut agg = [0u64; NR];
        if let Ok(Some(rows)) = self.skel.maps.cpu_ctx_stor.lookup_percpu(
            &0u32.to_ne_bytes(),
            libbpf_rs::MapFlags::ANY,
        ) {
            for row in rows {
                if row.len() < std::mem::size_of::<cpu_ctx>() {
                    continue;
                }
                // SAFETY: cpu_ctx is a POD layout shared with BPF.
                let cctx: &cpu_ctx = unsafe { &*(row.as_ptr() as *const cpu_ctx) };
                for (i, slot) in agg.iter_mut().enumerate() {
                    if i < cctx.stats.len() {
                        *slot = slot.saturating_add(cctx.stats[i]);
                    }
                }
            }
        }

        let game_ccd_now: u64 = if self.opts.game_ccd >= 0 {
            self.opts.game_ccd as u64
        } else {
            self.topo.default_game_ccd.max(0) as u64
        };

        Metrics {
            nr_cpus: self.topo.nr_cpu_ids as u64,
            nr_ccds: self.topo.nr_ccds as u64,
            is_x3d: if self.topo.is_x3d { 1 } else { 0 },
            is_gaming: if self.is_gaming { 1 } else { 0 },
            game_tgid: self.game_tgid as u64,
            game_ccd: game_ccd_now,
            nr_render: agg[zen3_stat_idx_STAT_RENDER_DISPATCHES as usize],
            nr_build: agg[zen3_stat_idx_STAT_BUILD_DISPATCHES as usize],
            nr_normal: agg[zen3_stat_idx_STAT_NORMAL_DISPATCHES as usize],
            nr_hog: agg[zen3_stat_idx_STAT_HOG_DISPATCHES as usize],
            nr_bg: agg[zen3_stat_idx_STAT_BG_DISPATCHES as usize],
            nr_local: agg[zen3_stat_idx_STAT_LOCAL_DISPATCHES as usize],
            nr_warm_stick: agg[zen3_stat_idx_STAT_WARM_STICK_HITS as usize],
            nr_cross_ccd: agg[zen3_stat_idx_STAT_CROSS_CCD_SPILLS as usize],
            nr_vprot_preempt: agg[zen3_stat_idx_STAT_VPROT_PREEMPTS as usize],
            nr_vprot_suppress: agg[zen3_stat_idx_STAT_VPROT_SUPPRESSED as usize],
            nr_hog_quota_block: agg[zen3_stat_idx_STAT_HOG_QUOTA_BLOCKS as usize],
            nr_reclass: agg[zen3_stat_idx_STAT_RECLASS_EVENTS as usize],
            nr_kthread_direct: agg[zen3_stat_idx_STAT_KTHREAD_DIRECT as usize],
        }
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        let detect_period = Duration::from_millis(250);
        let mut last_detect = Instant::now() - detect_period;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            let now = Instant::now();
            if now - last_detect >= detect_period {
                if let Err(e) = self.push_detection() {
                    warn!("push_detection: {}", e);
                }
                last_detect = now;
            }

            // Respond to stats requests with a short timeout so we keep
            // hitting the detection cadence.
            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    let m = self.collect_metrics();
                    res_ch.send(m)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    // Logging.
    let loglevel = if opts.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    // ctrl-C → graceful shutdown.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || {
            shutdown.store(true, Ordering::Relaxed);
        })
        .context("set ctrl-c")?;
    }

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown = shutdown.clone();
        let monitor_only = opts.monitor.is_some();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(Duration::from_secs_f64(intv), shutdown) {
                warn!("stats monitor: {}", e);
            }
        });
        if monitor_only {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(opts.clone(), &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

