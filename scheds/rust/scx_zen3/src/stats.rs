// SPDX-License-Identifier: GPL-2.0

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of online CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Number of CCDs (== L3 cache domains)")]
    pub nr_ccds: u64,
    #[stat(desc = "Whether 3D V-Cache (5800X3D) was detected")]
    pub is_x3d: u64,
    #[stat(desc = "1 if scheduler is currently in GAMING mode")]
    pub is_gaming: u64,
    #[stat(desc = "Detected game TGID, 0 if none")]
    pub game_tgid: u64,
    #[stat(desc = "Game-CCD id")]
    pub game_ccd: u64,
    #[stat(desc = "Render-class dispatches")]
    pub nr_render: u64,
    #[stat(desc = "Build-class dispatches")]
    pub nr_build: u64,
    #[stat(desc = "Normal-class dispatches")]
    pub nr_normal: u64,
    #[stat(desc = "Hog-class dispatches")]
    pub nr_hog: u64,
    #[stat(desc = "Bg-class dispatches")]
    pub nr_bg: u64,
    #[stat(desc = "Local direct dispatches (cache-warm or idle pick)")]
    pub nr_local: u64,
    #[stat(desc = "Cache-warm stickiness hits")]
    pub nr_warm_stick: u64,
    #[stat(desc = "Cross-CCD spills (render last-resort or build overflow)")]
    pub nr_cross_ccd: u64,
    #[stat(desc = "VPROT preemptions issued")]
    pub nr_vprot_preempt: u64,
    #[stat(desc = "VPROT preemptions suppressed (victim ran too short)")]
    pub nr_vprot_suppress: u64,
    #[stat(desc = "HOG dispatches blocked by quota on game CCD")]
    pub nr_hog_quota_block: u64,
    #[stat(desc = "Reclassification events")]
    pub nr_reclass: u64,
    #[stat(desc = "Direct dispatches of per-CPU kthreads (kernel fast path)")]
    pub nr_kthread_direct: u64,
}

impl Metrics {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[zen3] {} cpus/{} ccd{}{} | {} game={} ccd={} | \
             rdr={} bld={} nrm={} hog={} bg={} kth={} | \
             local={} warm={} xccd={} | vpro={} vsup={} hqb={}",
            self.nr_cpus,
            self.nr_ccds,
            if self.nr_ccds == 1 { "" } else { "s" },
            if self.is_x3d != 0 { " +X3D" } else { "" },
            if self.is_gaming != 0 { "GAMING" } else { "IDLE  " },
            self.game_tgid,
            self.game_ccd,
            self.nr_render,
            self.nr_build,
            self.nr_normal,
            self.nr_hog,
            self.nr_bg,
            self.nr_kthread_direct,
            self.nr_local,
            self.nr_warm_stick,
            self.nr_cross_ccd,
            self.nr_vprot_preempt,
            self.nr_vprot_suppress,
            self.nr_hog_quota_block,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_render: self.nr_render.saturating_sub(rhs.nr_render),
            nr_build: self.nr_build.saturating_sub(rhs.nr_build),
            nr_normal: self.nr_normal.saturating_sub(rhs.nr_normal),
            nr_hog: self.nr_hog.saturating_sub(rhs.nr_hog),
            nr_bg: self.nr_bg.saturating_sub(rhs.nr_bg),
            nr_local: self.nr_local.saturating_sub(rhs.nr_local),
            nr_warm_stick: self.nr_warm_stick.saturating_sub(rhs.nr_warm_stick),
            nr_cross_ccd: self.nr_cross_ccd.saturating_sub(rhs.nr_cross_ccd),
            nr_vprot_preempt: self.nr_vprot_preempt.saturating_sub(rhs.nr_vprot_preempt),
            nr_vprot_suppress: self.nr_vprot_suppress.saturating_sub(rhs.nr_vprot_suppress),
            nr_hog_quota_block: self.nr_hog_quota_block.saturating_sub(rhs.nr_hog_quota_block),
            nr_reclass: self.nr_reclass.saturating_sub(rhs.nr_reclass),
            nr_kthread_direct: self.nr_kthread_direct.saturating_sub(rhs.nr_kthread_direct),
            ..self.clone()
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
