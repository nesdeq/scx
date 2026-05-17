/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_zen3: Zen 3-specific sched_ext scheduler.
 *
 * This header is shared between the BPF program and the Rust userspace.
 */
#ifndef __SCX_ZEN3_INTF_H
#define __SCX_ZEN3_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif

enum zen3_consts {
	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC		= (1000ULL * NSEC_PER_MSEC),

	/*
	 * Capacities. MAX_CPUS=128 covers AM4 Vermeer (32T max) with
	 * generous headroom; we use 7 bits in the bitmap so 128 is
	 * also the natural ceiling.
	 */
	MAX_CPUS		= 128,
	MAX_CPUS_BITMAP_WORDS	= MAX_CPUS / 64,	/* 2 */
	MAX_CCDS		= 8,			/* covers Chagall too */
	MAX_CORES_PER_CCD	= 16,			/* 8c/16t per CCD */

	/* Family detection role bits (game_family_pids map value) */
	GAME_ROLE_FAMILY	= 1 << 0,
	GAME_ROLE_AUDIO		= 1 << 1,
	GAME_ROLE_COMPOSITOR	= 1 << 2,

	/* Probation: in-family thread newer than this stays BUILD class */
	PROBATION_NS		= 500ULL * NSEC_PER_MSEC,

	/* Confidence-gate stride: how often we reclassify (every Nth stop) */
	RECLASS_STRIDE		= 64,
};

enum task_class_e {
	CLASS_GAME_RENDER	= 0,
	CLASS_GAME_BUILD	= 1,
	CLASS_NORMAL		= 2,
	CLASS_HOG		= 3,
	CLASS_BG		= 4,
	NR_CLASSES,
};

/*
 * Statistics index — single source of truth across BPF/Rust. Used as the
 * cpu_ctx.stats[] array size; ISO C allows enum constants in array sizes.
 */
enum zen3_stat_idx {
	STAT_RENDER_DISPATCHES,
	STAT_BUILD_DISPATCHES,
	STAT_NORMAL_DISPATCHES,
	STAT_HOG_DISPATCHES,
	STAT_BG_DISPATCHES,
	STAT_LOCAL_DISPATCHES,
	STAT_WARM_STICK_HITS,
	STAT_CROSS_CCD_SPILLS,
	STAT_VPROT_PREEMPTS,
	STAT_VPROT_SUPPRESSED,
	STAT_HOG_QUOTA_BLOCKS,
	STAT_KTHREAD_DIRECT,
	STAT_RECLASS_EVENTS,
	NR_ZEN3_STATS,
};

/*
 * Per-CCD context. Stored in a BPF_MAP_TYPE_ARRAY of size MAX_CCDS.
 * Used exclusively for HOG quota accounting on the game CCD.
 */
struct ccd_ctx {
	/* Both counters reset every hog_quota_window_ns; `used` ticks on
	 * successful HOG dispatches, `total` on every quota check. The
	 * ratio describes HOG's share of CCD dispatch bandwidth. */
	u64			hog_quota_used;
	u64			hog_quota_total;
	u64			hog_quota_reset_at;
};

/*
 * Per-CPU context, in BPF_MAP_TYPE_PERCPU_ARRAY.
 *
 * Only fields that are actually read are kept here. CPU id and CCD id
 * are recoverable from the cpu_to_ccd[] rodata when needed.
 */
struct cpu_ctx {
	/* Class of currently running task; NR_CLASSES sentinel = idle.
	 * Read across CPUs by VPROT to decide whether to preempt. */
	u32			running_class;
	u32			pad0;
	/* When the currently-running task started (used by VPROT). */
	u64			run_start_at;
	/* Per-CPU stat counters; userspace folds them up. */
	u64			stats[NR_ZEN3_STATS];
};

/*
 * Per-task local storage.
 *
 * Timeline of timestamps (a typical wake → run → sleep cycle):
 *   last_quiescent_at ──── (sleeping) ──── last_woke_at
 *                                              │ (dispatch latency)
 *                                              v
 *                                       last_run_at  (= run start)
 *                                              │ (slice / preempt)
 *                                              v
 *                                       (next stopping)
 */
struct task_ctx {
	u32			class;
	u32			flags;			/* TASK_F_* */
	s32			last_cpu;
	u32			last_ccd;
	/* EWMA-scaled util_avg [0, 1024], wake-rate Hz. */
	u32			util_x1024;
	u32			wake_freq;
	/* When the most recent run began (stamped in running()). */
	u64			last_run_at;
	/* When select_cpu() saw this task wake. */
	u64			last_woke_at;
	/* When the most recent quiescent transition happened. */
	u64			last_quiescent_at;
	/* When this task entered the scheduler (init_task). */
	u64			created_at;
	/* EWMA of per-wake runtime + recent sleep duration (alpha = 1/4). */
	u64			avg_runtime;
	u64			avg_sleep;
};

#define TASK_F_IN_GAME_FAMILY	(1U << 0)
#define TASK_F_IS_ANTICHEAT	(1U << 1)
#define TASK_F_PROMOTED_RENDER	(1U << 2)	/* passed probation */

/*
 * Syscall program argument for re-pushing config from userspace.
 */
struct zen3_config_arg {
	u32			is_gaming;
	s32			game_ccd;
};

struct zen3_family_arg {
	pid_t			pid;
	u32			role_bits;	/* GAME_ROLE_* */
	u32			op;		/* 0=remove, 1=add */
	u32			pad0;
};

struct zen3_anticheat_arg {
	pid_t			pid;
	u32			op;		/* 0=remove, 1=add */
};

#endif /* __SCX_ZEN3_INTF_H */
