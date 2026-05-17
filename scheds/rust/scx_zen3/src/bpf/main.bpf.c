/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_zen3 — Zen 3-specific sched_ext scheduler.
 *
 * Targets frame-time consistency and 1%/0.1%-low latency in gaming workloads
 * on AM4 Vermeer (Ryzen 5000 desktop) and degrades sanely on Cezanne APUs.
 *
 * See ../../../../../scx_zen3.md for the design walkthrough and
 * ../../../../../zen3.md for the architecture reference.
 *
 * Two modes:
 *   IDLE   — flash-like EDF on per-CCD DSQs, no gaming heuristics.
 *   GAMING — class-aware, prefcore-policy placement, VPROT preempt,
 *            cache-warm-stick on vsync, hog rate-budget on game CCD.
 *
 * Five classes (in GAMING mode):
 *   GAME_RENDER — game family interactive threads (the render/sim pipeline).
 *   GAME_BUILD  — game family CPU-bound (shader compile, asset stream).
 *   NORMAL      — default desktop work.
 *   HOG         — out-of-family CPU-bound.
 *   BG          — nice >= 10 or otherwise demoted.
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * ─── rodata: set once from userspace before bpf_object__load. ───
 */
const volatile u32	nr_cpu_ids		= 1;
const volatile u32	nr_ccds			= 1;
const volatile u8	is_x3d			= 0;
const volatile u8	enable_cpufreq		= 1;
const volatile u8	enable_smt_avoidance	= 1;
const volatile u8	smt_enabled		= 1;
const volatile u32	cpu_to_ccd[MAX_CPUS];
const volatile u32	cpus_per_ccd[MAX_CCDS];
/* prefcore_rank_to_cpu[ccd][rank] : rank 0 = best */
const volatile u32	prefcore_rank_to_cpu[MAX_CCDS][MAX_CORES_PER_CCD];

const volatile u64	slice_render_ns		= 1500ULL * NSEC_PER_USEC;
const volatile u64	slice_build_ns		= 2000ULL * NSEC_PER_USEC;
const volatile u64	slice_normal_ns		= 2000ULL * NSEC_PER_USEC;
const volatile u64	slice_hog_ns		= 4000ULL * NSEC_PER_USEC;
const volatile u64	slice_bg_ns		= 4000ULL * NSEC_PER_USEC;
const volatile u64	warm_l3_ns		=  100000000ULL;
const volatile u32	hog_threshold_x1024	= 800;	/* ~78% */
const volatile u64	vprot_normal_ns		= 250ULL * NSEC_PER_USEC;
const volatile u64	vprot_hog_ns		=  50ULL * NSEC_PER_USEC;
const volatile u64	vprot_bg_ns		=  25ULL * NSEC_PER_USEC;
const volatile u64	hog_quota_window_ns	= 100ULL * NSEC_PER_MSEC;
const volatile u64	hog_quota_share_x1024	= 256;	/* 25% */

/*
 * Class weights, in vtime units. Chosen so even with sleep_bonus capped
 * at slice * 4, weights remain non-overlapping across classes.
 *
 *   GAME_RENDER  : [0,             6_000_000]
 *   GAME_BUILD   : [4_194_304_000, 4_200_304_000]   shift = 4096us
 *   NORMAL       : [8_388_608_000, 8_394_608_000]   shift = 8192us
 *   HOG          : [16_777_216_000, ...]            shift = 16384us
 *   BG           : [50_331_648_000, ...]            shift = 49152us
 */
const volatile u64	class_weight[NR_CLASSES] = {
	[CLASS_GAME_RENDER]	= 0ULL,
	[CLASS_GAME_BUILD]	= 4096ULL * NSEC_PER_USEC,
	[CLASS_NORMAL]		= 8192ULL * NSEC_PER_USEC,
	[CLASS_HOG]		= 16384ULL * NSEC_PER_USEC,
	[CLASS_BG]		= 49152ULL * NSEC_PER_USEC,
};

/*
 * ─── volatile globals: lock-free state set from userspace at runtime. ───
 */
volatile u32	is_gaming;
volatile s32	game_ccd	= -1;
volatile u64	game_cpu_mask[MAX_CPUS_BITMAP_WORDS];

/*
 * ─── maps ───
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct ccd_ctx);
	__uint(max_entries, MAX_CCDS);
} ccd_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, u32);		/* role bits */
	__uint(max_entries, 8192);
} game_family_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, u8);
	__uint(max_entries, 256);
} anticheat_pids SEC(".maps");

/*
 * ─── DSQ id derivation ───
 *
 * Bit layout:  [reserved][type:8][ccd:4]
 *
 *  DSQ_RENDER(ccd)   = 0x1000 | (ccd << 4) | 0x1
 *  DSQ_BUILD(ccd)    = 0x1000 | (ccd << 4) | 0x2
 *  DSQ_NORMAL(ccd)   = 0x1000 | (ccd << 4) | 0x3
 *  DSQ_HOG (global)  = 0x2001
 *  DSQ_BG  (global)  = 0x2002
 */
#define DSQ_PER_CCD_BASE	0x1000ULL
#define DSQ_GLOBAL_BASE		0x2000ULL
#define DSQ_HOG			(DSQ_GLOBAL_BASE | 0x1)
#define DSQ_BG			(DSQ_GLOBAL_BASE | 0x2)

static __always_inline u64 dsq_render(u32 ccd) { return DSQ_PER_CCD_BASE | ((u64)ccd << 4) | 0x1; }
static __always_inline u64 dsq_build (u32 ccd) { return DSQ_PER_CCD_BASE | ((u64)ccd << 4) | 0x2; }
static __always_inline u64 dsq_normal(u32 ccd) { return DSQ_PER_CCD_BASE | ((u64)ccd << 4) | 0x3; }

/*
 * ─── helpers ───
 */
static inline struct cpu_ctx *get_cpu_ctx(s32 cpu)
{
	const u32 zero = 0;

	if (cpu < 0)
		return bpf_map_lookup_elem(&cpu_ctx_stor, &zero);
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &zero, cpu);
}

static inline struct ccd_ctx *get_ccd_ctx(u32 ccd)
{
	if (ccd >= MAX_CCDS)
		return NULL;
	return bpf_map_lookup_elem(&ccd_ctx_stor, &ccd);
}

static inline struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static __always_inline u32 ccd_of_cpu(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return 0;
	return cpu_to_ccd[cpu];
}

/*
 * Pick "another" CCD given a current one. With nr_ccds == 1 just returns
 * the same CCD (callers must guard). With nr_ccds == 2 returns the other.
 * On >2 (Threadripper / EPYC), returns the *next* CCD modulo nr_ccds —
 * we don't have enough info to rank "best alternative" so round-robin.
 */
static __always_inline u32 other_ccd(u32 ccd)
{
	if (nr_ccds <= 1)
		return ccd;
	if (nr_ccds == 2)
		return ccd ^ 1u;
	return (ccd + 1u) % nr_ccds;
}

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static __always_inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline bool cpu_is_full_idle_smt(s32 cpu)
{
	const struct cpumask *smt_mask;
	bool ok;

	if (!smt_enabled)
		return scx_bpf_test_and_clear_cpu_idle(cpu) ? true : false;

	smt_mask = scx_bpf_get_idle_smtmask();
	ok = smt_mask ? bpf_cpumask_test_cpu(cpu, smt_mask) : false;
	if (smt_mask)
		scx_bpf_put_cpumask(smt_mask);

	return ok ? scx_bpf_test_and_clear_cpu_idle(cpu) : false;
}

static __always_inline bool game_mask_test(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return false;
	return game_cpu_mask[cpu / 64] & (1ULL << (cpu % 64));
}

static __always_inline void game_mask_set(u32 cpu)
{
	if (cpu < MAX_CPUS)
		__sync_fetch_and_or(&game_cpu_mask[cpu / 64], 1ULL << (cpu % 64));
}

static __always_inline void game_mask_clear(u32 cpu)
{
	if (cpu < MAX_CPUS)
		__sync_fetch_and_and(&game_cpu_mask[cpu / 64], ~(1ULL << (cpu % 64)));
}

static __always_inline void stat_inc(struct cpu_ctx *cctx, u32 idx)
{
	if (cctx && idx < NR_ZEN3_STATS)
		cctx->stats[idx]++;
}

/*
 * ─── classification ───
 *
 * In GAMING mode the class is determined every Nth stop. In between, the
 * cached class is reused. Probation: an in-family thread that hasn't
 * graduated to RENDER lives as BUILD.
 */
static u32 family_role(pid_t pid)
{
	u32 *v = bpf_map_lookup_elem(&game_family_pids, &pid);
	return v ? *v : 0;
}

static bool is_anticheat(pid_t pid)
{
	return bpf_map_lookup_elem(&anticheat_pids, &pid) != NULL;
}

static u32 classify_task(struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	u32 role;

	if (!tctx)
		return CLASS_NORMAL;

	/* Anticheat always demotes to HOG so it stays off the game CCD. */
	if (tctx->flags & TASK_F_IS_ANTICHEAT)
		return CLASS_HOG;

	/* Pinned per-cpu kthreads stay NORMAL — direct-dispatched anyway. */
	if (is_kthread(p) && is_pcpu_task(p))
		return CLASS_NORMAL;

	if (!is_gaming) {
		/* IDLE mode: only NORMAL / HOG / BG. */
		if (tctx->util_x1024 >= hog_threshold_x1024)
			return CLASS_HOG;
		if (p->scx.weight < 20)
			return CLASS_BG;
		return CLASS_NORMAL;
	}

	/* GAMING mode. */
	role = tctx->flags & TASK_F_IN_GAME_FAMILY ? family_role(p->pid) : 0;

	if (role & GAME_ROLE_FAMILY) {
		/* Probation: in-family threads younger than PROBATION_NS or
		 * still CPU-bound stay as BUILD. */
		if (now - tctx->created_at < PROBATION_NS &&
		    !(tctx->flags & TASK_F_PROMOTED_RENDER))
			return CLASS_GAME_BUILD;

		if (tctx->util_x1024 >= hog_threshold_x1024 &&
		    !(tctx->flags & TASK_F_PROMOTED_RENDER))
			return CLASS_GAME_BUILD;

		return CLASS_GAME_RENDER;
	}

	if (role & (GAME_ROLE_AUDIO | GAME_ROLE_COMPOSITOR))
		return CLASS_GAME_RENDER;

	if (tctx->util_x1024 >= hog_threshold_x1024)
		return CLASS_HOG;
	if (p->scx.weight < 20)
		return CLASS_BG;
	return CLASS_NORMAL;
}

/*
 * Promote in-family tasks that are CPU-quiet and wake often (the render
 * thread shape); demote ones that turn CPU-bound (catches shader-compile
 * bursts from worker-pool reuse). Re-runs classify_task() afterwards.
 */
static void reclassify(struct task_struct *p, struct task_ctx *tctx,
		       struct cpu_ctx *cctx, u64 now)
{
	bool in_family = tctx->flags & TASK_F_IN_GAME_FAMILY;
	bool promoted  = tctx->flags & TASK_F_PROMOTED_RENDER;
	u32 cpu_quiet  = (hog_threshold_x1024 / 2);

	if (in_family) {
		if (!promoted &&
		    tctx->util_x1024 < cpu_quiet &&
		    tctx->wake_freq >= 20)
			tctx->flags |= TASK_F_PROMOTED_RENDER;
		else if (promoted &&
			 tctx->util_x1024 >= hog_threshold_x1024)
			tctx->flags &= ~TASK_F_PROMOTED_RENDER;
	}

	tctx->class = classify_task(p, tctx, now);
	stat_inc(cctx, STAT_RECLASS_EVENTS);
}

/*
 * Task slice in ns based on class. Defined before task_dl so the latter
 * can reference it without a forward declaration.
 */
static __always_inline u64 task_slice(u32 class)
{
	switch (class) {
	case CLASS_GAME_RENDER:	return slice_render_ns;
	case CLASS_GAME_BUILD:	return slice_build_ns;
	case CLASS_NORMAL:	return slice_normal_ns;
	case CLASS_HOG:		return slice_hog_ns;
	case CLASS_BG:		return slice_bg_ns;
	}
	return slice_normal_ns;
}

/*
 * ─── vtime / deadline ───
 *
 * Within a class, ordering is by:
 *    vtime = now + class_weight[c] + nice_offset(p) - sleep_bonus
 *
 * sleep_bonus is clamped so a long sleeper can't pre-empt forever.
 */
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx, u32 class, u64 now)
{
	u64 base = now + class_weight[class];
	u64 slice = task_slice(class);
	u64 lag_cap = slice * 4;
	u64 sleep_bonus = 0;
	u64 nice_offset = 0;

	/*
	 * Nice / weight bias. p->scx.weight is the CFS-style weight (100 =
	 * nice 0). Weight < 100 → positive nice → push deadline later.
	 * Weight > 100 → negative nice → pull deadline earlier.
	 */
	if (p->scx.weight < 100) {
		nice_offset = (100u - p->scx.weight) * (slice / 32);
	} else if (p->scx.weight > 100) {
		u32 over = p->scx.weight - 100u;
		if (over > 100u) over = 100u;
		base -= over * (slice / 64);
	}
	base += nice_offset;

	/*
	 * Sleep bonus: how long this task slept since last quiescent.
	 *
	 *   quiescent_at ──── (sleeping) ──── woke_at
	 *                                       │
	 *                                       v (now ≈ this enqueue)
	 *
	 * Bonus = slept / 16, clamped to lag_cap (4× slice). Caller subtracts
	 * from base, so longer sleepers get smaller (earlier) deadlines.
	 */
	if (tctx->last_quiescent_at &&
	    tctx->last_woke_at > tctx->last_quiescent_at) {
		u64 slept = tctx->last_woke_at - tctx->last_quiescent_at;
		sleep_bonus = slept >> 4;
		if (sleep_bonus > lag_cap)
			sleep_bonus = lag_cap;
	}

	return base > sleep_bonus ? base - sleep_bonus : 0;
}

/*
 * Target DSQ for a class+ccd pair.
 */
static __always_inline u64 dsq_for_class(u32 class, u32 ccd)
{
	switch (class) {
	case CLASS_GAME_RENDER:	return dsq_render(ccd);
	case CLASS_GAME_BUILD:	return dsq_build(ccd);
	case CLASS_NORMAL:	return dsq_normal(ccd);
	case CLASS_HOG:		return DSQ_HOG;
	case CLASS_BG:		return DSQ_BG;
	}
	return dsq_normal(ccd);
}

/*
 * ─── idle CPU picking ───
 *
 * Scan the prefcore rank list for `ccd`, returning the first idle CPU
 * usable by @p. If @need_smt_idle, only return full-idle SMT cores
 * (avoids stacking on a hot physical core's sibling).
 *
 * @start_rank lets the caller skip top-N ranks (e.g. GAME_BUILD scans
 * from rank 2 onwards to leave the top cores for render).
 */
static __always_inline s32 pick_idle_in_ccd(struct task_struct *p, u32 ccd,
					    u32 start_rank, bool need_smt_idle)
{
	u32 i, max_rank;

	if (ccd >= MAX_CCDS)
		return -ENOENT;

	max_rank = cpus_per_ccd[ccd];
	if (max_rank > MAX_CORES_PER_CCD)
		max_rank = MAX_CORES_PER_CCD;

	bpf_for(i, start_rank, max_rank) {
		u32 cpu;

		if (i >= MAX_CORES_PER_CCD)
			break;

		cpu = prefcore_rank_to_cpu[ccd][i];
		if (cpu >= MAX_CPUS || cpu >= nr_cpu_ids)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		if (need_smt_idle) {
			if (!cpu_is_full_idle_smt(cpu))
				continue;
		} else {
			if (!scx_bpf_test_and_clear_cpu_idle(cpu))
				continue;
		}
		return cpu;
	}
	return -ENOENT;
}

/*
 * Reverse-prefcore scan (for HOG/BG: prefer slow cores).
 *
 * Implemented as a forward bpf_for with computed reverse index so the
 * verifier can prove termination via the bounded-loop annotation that
 * the bpf_for macro emits.
 */
static s32 pick_idle_in_ccd_reverse(struct task_struct *p, u32 ccd)
{
	u32 i, max_rank;

	if (ccd >= MAX_CCDS)
		return -ENOENT;

	max_rank = cpus_per_ccd[ccd];
	if (max_rank > MAX_CORES_PER_CCD)
		max_rank = MAX_CORES_PER_CCD;
	if (max_rank == 0)
		return -ENOENT;

	bpf_for(i, 0, max_rank) {
		u32 idx, cpu;

		if (i >= MAX_CORES_PER_CCD)
			break;

		idx = max_rank - 1 - i;
		if (idx >= MAX_CORES_PER_CCD)
			continue;

		cpu = prefcore_rank_to_cpu[ccd][idx];
		if (cpu >= MAX_CPUS || cpu >= nr_cpu_ids)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}
	return -ENOENT;
}

/*
 * Determine which CCD is the "game CCD" right now.
 *
 * Userspace can pin it via `game_ccd`. Otherwise we pick CCD 0 (typically
 * holds the highest-ranked prefcore on dual-CCD Vermeer).
 */
static __always_inline u32 current_game_ccd(void)
{
	s32 g = game_ccd;

	if (g >= 0 && g < (s32)nr_ccds)
		return (u32)g;
	return 0;
}

/*
 * Cache-warm stickiness: if task last ran on @cpu within warm_l3_ns AND
 * that CPU is still idle, pin back. The idle reservation is claimed
 * only after the time-window check passes — leaking the reservation on
 * the cold path was a previous bug.
 */
static bool warm_stick(struct task_struct *p, struct task_ctx *tctx,
		       struct cpu_ctx *cctx, u64 now, s32 *cpu_out)
{
	s32 cpu;
	u64 elapsed;

	if (!tctx || tctx->last_cpu < 0 || tctx->last_cpu >= (s32)nr_cpu_ids)
		return false;

	cpu = tctx->last_cpu;
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;

	elapsed = time_delta(now, tctx->last_run_at);
	if (elapsed > warm_l3_ns)
		return false;	/* cache cold — no stickiness */

	/*
	 * Within the warm window. Claim the idle bit; if someone else got
	 * there first, fall back to the normal placement path.
	 */
	if (!scx_bpf_test_and_clear_cpu_idle(cpu))
		return false;

	stat_inc(cctx, STAT_WARM_STICK_HITS);
	*cpu_out = cpu;
	return true;
}

/*
 * ─── select_cpu ───
 */
s32 BPF_STRUCT_OPS(zen3_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct cpu_ctx *cctx = get_cpu_ctx(-1);
	struct task_ctx *tctx;
	u64 now;
	s32 cpu;
	u32 class, ccd_pref;
	u32 g_ccd;
	bool need_smt;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	now = scx_bpf_now();
	tctx->last_woke_at = now;

	/* Pinned to a single CPU: skip the whole machinery. */
	if (p->nr_cpus_allowed == 1) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice(tctx->class), 0);
			stat_inc(cctx, STAT_LOCAL_DISPATCHES);
		}
		return prev_cpu;
	}

	class = tctx->class;
	g_ccd = current_game_ccd();

	/* IDLE mode: stock idle pick + fall through to enqueue. */
	if (!is_gaming) {
		bool is_idle = false;

		if (__COMPAT_HAS_scx_bpf_select_cpu_and) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
						     p->cpus_ptr, 0);
			if (cpu >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
						   task_slice(class), 0);
				stat_inc(cctx, STAT_LOCAL_DISPATCHES);
				return cpu;
			}
		} else {
			cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags,
						     &is_idle);
			if (is_idle) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
						   task_slice(class), 0);
				stat_inc(cctx, STAT_LOCAL_DISPATCHES);
				return cpu;
			}
		}
		return prev_cpu;
	}

	/* GAMING mode. */

	/* Cache-warm stickiness for GAME_RENDER vsync wakes. */
	if (class == CLASS_GAME_RENDER) {
		s32 sticky_cpu;
		if (warm_stick(p, tctx, cctx, now, &sticky_cpu) && sticky_cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice(class), 0);
			stat_inc(cctx, STAT_LOCAL_DISPATCHES);
			return sticky_cpu;
		}
	}

	switch (class) {
	case CLASS_GAME_RENDER:
	case CLASS_GAME_BUILD:
		ccd_pref = g_ccd;
		break;
	case CLASS_NORMAL:
		ccd_pref = tctx->last_ccd < nr_ccds ? tctx->last_ccd : g_ccd;
		break;
	case CLASS_HOG:
	case CLASS_BG:
	default:
		/* Anti-affinity to game CCD on multi-CCD; degenerates to
		 * the same CCD on single-CCD parts (reverse scan handles
		 * the slow-end preference there). */
		ccd_pref = nr_ccds > 1 ? other_ccd(g_ccd) : 0;
		break;
	}

	/*
	 * GAME_RENDER placement ladder. SMT siblings share L1/L2 and
	 * execution units on Zen 3; two hot threads on one physical core
	 * cost more than an 80 ns IF hop. So a full-idle SMT core on the
	 * other CCD always wins over a sibling-stack on the game CCD.
	 *
	 *   1. Full-idle SMT core on game CCD.
	 *   2. Full-idle SMT core on other CCD (cross-CCD before stack).
	 *   3. Sibling-stack on game CCD (cache-warm, degraded).
	 *   4. Sibling-stack on other CCD (last resort).
	 */
	if (class == CLASS_GAME_RENDER) {
		need_smt = enable_smt_avoidance && smt_enabled;

		cpu = pick_idle_in_ccd(p, ccd_pref, 0, need_smt);
		if (cpu < 0 && nr_ccds > 1 && need_smt) {
			cpu = pick_idle_in_ccd(p, other_ccd(g_ccd), 0, true);
			if (cpu >= 0)
				stat_inc(cctx, STAT_CROSS_CCD_SPILLS);
		}
		if (cpu < 0)
			cpu = pick_idle_in_ccd(p, ccd_pref, 0, false);
		if (cpu < 0 && nr_ccds > 1) {
			cpu = pick_idle_in_ccd(p, other_ccd(g_ccd), 0, false);
			if (cpu >= 0)
				stat_inc(cctx, STAT_CROSS_CCD_SPILLS);
		}
		goto direct_or_prev;
	}

	/* GAME_BUILD: skip top-2 prefcores in game CCD.
	 *
	 * SMT-stacking on the game CCD is worse than cross-CCD spill for
	 * compute-bound workers (shared execution units > 80ns IF hop). So:
	 *   1. Full-idle SMT on game CCD (rank ≥ start).
	 *   2. Full-idle SMT on other CCD before stacking siblings.
	 *   3. Any idle on game CCD (sibling-stacking allowed).
	 *   4. Any idle on other CCD (last resort).
	 */
	if (class == CLASS_GAME_BUILD) {
		u32 start = (cpus_per_ccd[ccd_pref] >= 4) ? 2 : 0;
		bool need_smt = enable_smt_avoidance && smt_enabled;

		cpu = pick_idle_in_ccd(p, ccd_pref, start, need_smt);
		if (cpu < 0 && nr_ccds > 1 && need_smt) {
			cpu = pick_idle_in_ccd(p, other_ccd(g_ccd), 0, true);
			if (cpu >= 0)
				stat_inc(cctx, STAT_CROSS_CCD_SPILLS);
		}
		if (cpu < 0)
			cpu = pick_idle_in_ccd(p, ccd_pref, start, false);
		if (cpu < 0 && nr_ccds > 1) {
			cpu = pick_idle_in_ccd(p, other_ccd(g_ccd), 0, false);
			if (cpu >= 0)
				stat_inc(cctx, STAT_CROSS_CCD_SPILLS);
		}
		goto direct_or_prev;
	}

	/* NORMAL: try task's last CCD, then other. */
	if (class == CLASS_NORMAL) {
		cpu = pick_idle_in_ccd(p, ccd_pref, 0, false);
		if (cpu < 0 && nr_ccds > 1)
			cpu = pick_idle_in_ccd(p, other_ccd(ccd_pref), 0, false);
		goto direct_or_prev;
	}

	/* HOG/BG: reverse-prefcore on anti-game CCD. */
	cpu = pick_idle_in_ccd_reverse(p, ccd_pref);
	if (cpu < 0 && nr_ccds > 1)
		cpu = pick_idle_in_ccd_reverse(p, other_ccd(ccd_pref));

direct_or_prev:
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(class), 0);
		stat_inc(cctx, STAT_LOCAL_DISPATCHES);
		return cpu;
	}
	return prev_cpu;
}

/*
 * ─── VPROT: preempt a non-GAME victim on the game CCD ───
 */
static void try_vprot_preempt(struct task_struct *p, u64 now)
{
	u32 g_ccd = current_game_ccd();
	u32 i, max_rank;

	max_rank = cpus_per_ccd[g_ccd];
	if (max_rank > MAX_CORES_PER_CCD)
		max_rank = MAX_CORES_PER_CCD;

	bpf_for(i, 0, max_rank) {
		u32 cpu;
		struct cpu_ctx *vcctx;
		u64 elapsed, vprot_ns;
		u32 vclass;

		if (i >= MAX_CORES_PER_CCD)
			break;

		cpu = prefcore_rank_to_cpu[g_ccd][i];
		if (cpu >= MAX_CPUS || cpu >= nr_cpu_ids)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (game_mask_test(cpu))
			continue; /* already running GAME */

		vcctx = get_cpu_ctx(cpu);
		if (!vcctx)
			continue;

		vclass = vcctx->running_class;
		switch (vclass) {
		case CLASS_NORMAL:	vprot_ns = vprot_normal_ns;	break;
		case CLASS_HOG:		vprot_ns = vprot_hog_ns;	break;
		case CLASS_BG:		vprot_ns = vprot_bg_ns;	break;
		default:		continue;
		}

		elapsed = time_delta(now, vcctx->run_start_at);
		if (elapsed >= vprot_ns) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			stat_inc(vcctx, STAT_VPROT_PREEMPTS);
			return;
		}
		stat_inc(vcctx, STAT_VPROT_SUPPRESSED);
	}
}

/*
 * ─── enqueue ───
 */
void BPF_STRUCT_OPS(zen3_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx = get_cpu_ctx(-1);
	struct task_ctx *tctx;
	u32 class, ccd;
	u64 now, dl, slice, target_dsq;
	s32 prev_cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	now = scx_bpf_now();

	/* per-cpu kthread fast-path */
	if (is_kthread(p) && is_pcpu_task(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_normal_ns, enq_flags);
		stat_inc(cctx, STAT_KTHREAD_DIRECT);
		return;
	}

	/*
	 * Classify on every enqueue: GAME mode transitions and new family
	 * memberships need to take effect immediately, not after the next
	 * reclass tick. classify_task() is cheap — one map lookup + branches.
	 */
	tctx->class = classify_task(p, tctx, now);
	class = tctx->class;

	prev_cpu = scx_bpf_task_cpu(p);
	ccd = (prev_cpu >= 0 && prev_cpu < (s32)nr_cpu_ids) ?
		ccd_of_cpu(prev_cpu) : current_game_ccd();

	if (is_gaming) {
		u32 g_ccd = current_game_ccd();
		switch (class) {
		case CLASS_GAME_RENDER:
		case CLASS_GAME_BUILD:
			ccd = g_ccd;
			break;
		case CLASS_HOG:
		case CLASS_BG:
			if (nr_ccds > 1)
				ccd = other_ccd(g_ccd);
			break;
		default:
			break;
		}
	}

	dl = task_dl(p, tctx, class, now);
	slice = task_slice(class);
	target_dsq = dsq_for_class(class, ccd);

	tctx->last_ccd = ccd;

	if (target_dsq == DSQ_BG) {
		/* BG is FIFO; deadline doesn't drive ordering there. */
		scx_bpf_dsq_insert(p, DSQ_BG, slice, enq_flags);
	} else {
		scx_bpf_dsq_insert_vtime(p, target_dsq, slice, dl, enq_flags);
	}

	switch (class) {
	case CLASS_GAME_RENDER:	stat_inc(cctx, STAT_RENDER_DISPATCHES);	break;
	case CLASS_GAME_BUILD:	stat_inc(cctx, STAT_BUILD_DISPATCHES);	break;
	case CLASS_NORMAL:	stat_inc(cctx, STAT_NORMAL_DISPATCHES);	break;
	case CLASS_HOG:		stat_inc(cctx, STAT_HOG_DISPATCHES);	break;
	case CLASS_BG:		stat_inc(cctx, STAT_BG_DISPATCHES);	break;
	}

	if (is_gaming && class == CLASS_GAME_RENDER)
		try_vprot_preempt(p, now);

	/* Kick the chosen CCD's top prefcore if select_cpu didn't already. */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && ccd < MAX_CCDS) {
		u32 first = prefcore_rank_to_cpu[ccd][0];
		if (first < nr_cpu_ids)
			scx_bpf_kick_cpu((s32)first, SCX_KICK_IDLE);
	}
}

/*
 * ─── hog rate-budget ───
 *
 * Limits HOG-class dispatches on the game CCD to at most
 *   hog_quota_share_x1024 / 1024  (default 25%)
 * of the dispatch attempts within a hog_quota_window_ns rolling window.
 *
 * Both counters are post-decision:
 *   total ticks once per dispatch attempt on this CCD (allowed or not).
 *   used  ticks only when an attempt actually moved a HOG task.
 *
 * That way the ratio used/total accurately reflects HOG's slice of the
 * CCD's dispatch bandwidth.
 */
static bool hog_quota_allows(u32 ccd, u64 now)
{
	struct ccd_ctx *gctx = get_ccd_ctx(ccd);

	if (!gctx)
		return true;	/* fail-open */

	if (gctx->hog_quota_reset_at == 0 ||
	    time_delta(now, gctx->hog_quota_reset_at) >= hog_quota_window_ns) {
		gctx->hog_quota_reset_at = now;
		gctx->hog_quota_used = 0;
		gctx->hog_quota_total = 0;
	}

	gctx->hog_quota_total++;

	/* used / total > share / 1024 ⇒ over budget → block */
	return gctx->hog_quota_used * 1024 <=
	       hog_quota_share_x1024 * gctx->hog_quota_total;
}

static void hog_quota_charge(u32 ccd)
{
	struct ccd_ctx *gctx = get_ccd_ctx(ccd);
	if (gctx)
		gctx->hog_quota_used++;
}

/*
 * ─── dispatch ───
 */
void BPF_STRUCT_OPS(zen3_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx = get_cpu_ctx(-1);
	u64 now = scx_bpf_now();
	u32 ccd = ccd_of_cpu(cpu);
	u32 g_ccd = current_game_ccd();
	bool on_game_ccd = (ccd == g_ccd);

	if (is_gaming) {
		if (on_game_ccd) {
			if (scx_bpf_dsq_move_to_local(dsq_render(ccd), 0))
				return;
			if (scx_bpf_dsq_move_to_local(dsq_build(ccd), 0))
				return;
			if (scx_bpf_dsq_move_to_local(dsq_normal(ccd), 0))
				return;
			if (hog_quota_allows(ccd, now)) {
				if (scx_bpf_dsq_move_to_local(DSQ_HOG, 0)) {
					hog_quota_charge(ccd);
					return;
				}
			} else {
				stat_inc(cctx, STAT_HOG_QUOTA_BLOCKS);
			}
			if (scx_bpf_dsq_move_to_local(DSQ_BG, 0))
				return;
		} else {
			/* non-game CCD: NORMAL local first, then absorb HOG/BG. */
			if (scx_bpf_dsq_move_to_local(dsq_normal(ccd), 0))
				return;
			/* Build can spill cross-CCD. */
			if (scx_bpf_dsq_move_to_local(dsq_build(g_ccd), 0))
				return;
			if (scx_bpf_dsq_move_to_local(DSQ_HOG, 0))
				return;
			if (scx_bpf_dsq_move_to_local(DSQ_BG, 0))
				return;
			/* Last resort: render (cache-cold, but better than idle) */
			if (scx_bpf_dsq_move_to_local(dsq_render(g_ccd), 0)) {
				stat_inc(cctx, STAT_CROSS_CCD_SPILLS);
				return;
			}
		}
	} else {
		/* IDLE mode: drain local CCD first, then any other CCD. */
		if (scx_bpf_dsq_move_to_local(dsq_normal(ccd), 0))
			return;
		if (nr_ccds > 1 &&
		    scx_bpf_dsq_move_to_local(dsq_normal(other_ccd(ccd)), 0))
			return;
		if (scx_bpf_dsq_move_to_local(DSQ_HOG, 0))
			return;
		if (scx_bpf_dsq_move_to_local(DSQ_BG, 0))
			return;
	}

	/* Nothing to dispatch; keep prev running if it wants to. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct task_ctx *ptctx = try_lookup_task_ctx(prev);
		if (ptctx)
			prev->scx.slice = task_slice(ptctx->class);
	}
}

/*
 * ─── lifecycle ───
 */
void BPF_STRUCT_OPS(zen3_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	u64 now;

	if (!tctx)
		return;

	now = scx_bpf_now();

	/*
	 * Wake-frequency EWMA. Measured wake → wake interval since the
	 * previous wake observation.
	 */
	if (tctx->last_woke_at && now > tctx->last_woke_at) {
		u64 delta = now - tctx->last_woke_at;
		u32 new_freq = (u32)(NSEC_PER_SEC / delta);
		tctx->wake_freq = (tctx->wake_freq * 3 + new_freq) / 4;
	}
	/*
	 * Update the EWMA of sleep duration (used by util_x1024 next stop).
	 * Sleep is bounded by 1 s to keep one big nap from biasing the avg.
	 */
	if (tctx->last_quiescent_at && now > tctx->last_quiescent_at) {
		u64 slept = now - tctx->last_quiescent_at;
		if (slept > NSEC_PER_SEC)
			slept = NSEC_PER_SEC;
		tctx->avg_sleep = (tctx->avg_sleep * 3 + slept) / 4;
	}
}

void BPF_STRUCT_OPS(zen3_running, struct task_struct *p)
{
	struct cpu_ctx *cctx = get_cpu_ctx(-1);
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	/*
	 * scx_bpf_cpuperf_set() requires the target CPU to match the
	 * currently-locked rq. In ops.running, that's the task's CPU —
	 * not necessarily bpf_get_smp_processor_id() under migration.
	 */
	s32 cpu = scx_bpf_task_cpu(p);
	u64 now = scx_bpf_now();
	u32 ccd = ccd_of_cpu(cpu);

	if (cctx) {
		cctx->run_start_at = now;
		cctx->running_class = tctx ? tctx->class : CLASS_NORMAL;
	}

	if (!tctx)
		return;

	tctx->last_cpu = cpu;
	tctx->last_ccd = ccd;
	tctx->last_run_at = now;

	if (tctx->class == CLASS_GAME_RENDER)
		game_mask_set(cpu);
	else
		game_mask_clear(cpu);

	/* CPUPERF nudging — skipped on X3D. */
	if (enable_cpufreq && !is_x3d) {
		u32 perf = SCX_CPUPERF_ONE / 2;

		switch (tctx->class) {
		case CLASS_GAME_RENDER:	perf = SCX_CPUPERF_ONE;		break;
		case CLASS_GAME_BUILD:	perf = SCX_CPUPERF_ONE * 3 / 4;	break;
		case CLASS_NORMAL:	perf = SCX_CPUPERF_ONE * 3 / 4;	break;
		case CLASS_HOG:		perf = SCX_CPUPERF_ONE / 2;	break;
		case CLASS_BG:		perf = SCX_CPUPERF_ONE / 4;	break;
		}
		scx_bpf_cpuperf_set(cpu, perf);
	}
}

void BPF_STRUCT_OPS(zen3_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx = get_cpu_ctx(-1);
	struct task_ctx *tctx = try_lookup_task_ctx(p);
	s32 cpu = bpf_get_smp_processor_id();
	u64 now = scx_bpf_now();
	u64 elapsed;
	static u32 reclass_counter;

	if (cctx)
		cctx->running_class = NR_CLASSES;	/* sentinel: idle */

	if (!tctx)
		return;

	elapsed = time_delta(now, tctx->last_run_at);

	/* avg_runtime EWMA, alpha = 1/4. */
	tctx->avg_runtime = (tctx->avg_runtime * 3 + elapsed) / 4;

	/*
	 * util_x1024 = run / (run + sleep), scaled by 1024.
	 *
	 * Uses EWMAs (avg_runtime, avg_sleep) instead of single-cycle
	 * values so a single long sleep doesn't crater util to 0 in one
	 * cycle. avg_sleep is updated in runnable().
	 */
	{
		u64 r = tctx->avg_runtime;
		u64 s = tctx->avg_sleep;
		u64 cycle = r + s;
		if (cycle)
			tctx->util_x1024 = (u32)((r * 1024ULL) / cycle);
	}

	game_mask_clear(cpu);

	/*
	 * Quiescent transition: task is going to sleep. Stamp the time so
	 * the next wakeup can compute sleep duration. We piggyback off
	 * stopping() because quiescent() arrives later and we want this
	 * timestamp tight against the runnable() wake observation.
	 */
	if (!runnable)
		tctx->last_quiescent_at = now;

	/*
	 * Background reclassification cadence. enqueue() already classifies
	 * eagerly; this is a safety net for tasks that stop frequently but
	 * never re-enqueue through the gaming fast path (e.g. cgroup-loaded
	 * cpuset-pinned threads).
	 */
	if ((++reclass_counter % RECLASS_STRIDE) == 0)
		reclassify(p, tctx, cctx, now);
}

s32 BPF_STRUCT_OPS(zen3_init_task, struct task_struct *p,
		    struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now = scx_bpf_now();

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/* Task storage is zero-initialised; only explicitly set the
	 * fields whose desired initial value isn't zero. */
	tctx->last_cpu = -1;
	tctx->class = CLASS_NORMAL;
	tctx->created_at = now;
	tctx->last_quiescent_at = now;

	if (family_role(p->pid) & GAME_ROLE_FAMILY)
		tctx->flags |= TASK_F_IN_GAME_FAMILY;
	if (is_anticheat(p->pid))
		tctx->flags |= TASK_F_IS_ANTICHEAT;

	return 0;
}

/*
 * ─── init / exit ───
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(zen3_init)
{
	u32 ccd;
	int err;

	bpf_for(ccd, 0, nr_ccds) {
		err = scx_bpf_create_dsq(dsq_render(ccd), -1);
		if (err) return err;
		err = scx_bpf_create_dsq(dsq_build(ccd), -1);
		if (err) return err;
		err = scx_bpf_create_dsq(dsq_normal(ccd), -1);
		if (err) return err;
	}

	err = scx_bpf_create_dsq(DSQ_HOG, -1);
	if (err) return err;
	err = scx_bpf_create_dsq(DSQ_BG, -1);
	if (err) return err;

	return 0;
}

void BPF_STRUCT_OPS(zen3_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * ─── syscall programs (called by userspace) ───
 */
SEC("syscall")
int zen3_set_state(struct zen3_config_arg *arg)
{
	if (!arg)
		return -EINVAL;
	is_gaming = arg->is_gaming;
	if (arg->game_ccd >= -1 && arg->game_ccd < (s32)nr_ccds)
		game_ccd = arg->game_ccd;
	return 0;
}

SEC("syscall")
int zen3_update_family(struct zen3_family_arg *arg)
{
	pid_t pid;
	u32 v;

	if (!arg)
		return -EINVAL;

	/* The verifier requires map keys to live on the BPF stack, not in
	 * the ctx struct. Copy through locals. */
	pid = arg->pid;

	if (arg->op == 1) {
		v = arg->role_bits ? arg->role_bits : GAME_ROLE_FAMILY;
		bpf_map_update_elem(&game_family_pids, &pid, &v, BPF_ANY);
	} else {
		bpf_map_delete_elem(&game_family_pids, &pid);
	}
	return 0;
}

SEC("syscall")
int zen3_update_anticheat(struct zen3_anticheat_arg *arg)
{
	pid_t pid;
	u8 one = 1;

	if (!arg)
		return -EINVAL;

	/* Stack-local copy: see zen3_update_family for rationale. */
	pid = arg->pid;

	if (arg->op == 1)
		bpf_map_update_elem(&anticheat_pids, &pid, &one, BPF_ANY);
	else
		bpf_map_delete_elem(&anticheat_pids, &pid);
	return 0;
}

SCX_OPS_DEFINE(zen3_ops,
	       .select_cpu	= (void *)zen3_select_cpu,
	       .enqueue		= (void *)zen3_enqueue,
	       .dispatch	= (void *)zen3_dispatch,
	       .runnable	= (void *)zen3_runnable,
	       .running		= (void *)zen3_running,
	       .stopping	= (void *)zen3_stopping,
	       .init_task	= (void *)zen3_init_task,
	       .init		= (void *)zen3_init,
	       .exit		= (void *)zen3_exit,
	       .timeout_ms	= 5000,
	       .name		= "zen3");
