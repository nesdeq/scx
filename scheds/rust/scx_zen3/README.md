# scx_zen3

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

A `sched_ext` scheduler purpose-built for AMD Zen 3 desktop CPUs (Ryzen 5000 series — Vermeer, including the 5800X3D). It hard-codes the Zen 3 reality — CCDs as cache domains, CPPC preferred-core ranking, SMT siblings sharing execution units, V-Cache voltage clamps — rather than deriving placement from generic topology abstractions.

Two operating modes, switched automatically:

* **GAMING** — entered when a Steam env var (`SteamGameId`) or a Wine/Proton `.exe` cmdline is detected on a process. The detector also identifies the game family (descendant processes), audio daemons (PipeWire/PulseAudio), and Wayland/X11 compositors so they can be co-scheduled with render.

* **IDLE** — when no game is present, behaves like a Flash-style EDF scheduler with per-CCD DSQs.

Five task classes drive placement and preemption:

* `GAME_RENDER` — game-family interactive threads (render / sim / RHI). Pinned to the game CCD's firmware-ranked preferred cores. Prefers full-idle SMT cores; spills to the other CCD before stacking on a sibling. Cache-warm sticky on vsync re-wakes within 100 ms.
* `GAME_BUILD` — game-family CPU-bound (shader compile, asset stream). Pinned to game CCD but skips the top-2 prefcores reserved for render. Same SMT-aware ladder.
* `NORMAL` — default desktop work. Prefers task's last CCD.
* `HOG` — out-of-family CPU-bound. Anti-affinity to game CCD; reverse-prefcore scan picks slow cores first. Capped at 25 % of the game CCD's dispatch bandwidth while gaming.
* `BG` — `nice ≥ 10` or otherwise demoted. FIFO ordering, lowest priority.

Render arriving on a busy game CCD can preempt a non-game victim via VPROT, with class-tiered protection windows (NORMAL=250µs, HOG=50µs, BG=25µs).

Auto-detects 5800X3D from L3 size and disables `scx_bpf_cpuperf_set` nudging — the V-Cache stack can't tolerate the voltage push.

## Typical Use Case

Single-socket AM4 Ryzen 5000 desktops running games, especially titles with multiple heavy threads (UE5, modern AAA). The scheduler aims at frame-time consistency and 1%/0.1%-low latency, not throughput. Non-gaming sessions degrade gracefully to a generic EDF policy.

Not tuned for: Threadripper / EPYC (multi-CCD heuristics fall back to round-robin), Cezanne mobile, or pure-throughput workloads (compile, encode) — for those, `scx_flash` or `scx_bpfland` are better defaults.

Requirements:
* Linux ≥ 6.16 with `CONFIG_SCHED_CLASS_EXT=y`.
* `amd-pstate` active or guided, with CPPC preferred-core ranking enabled.
* Root (CAP_SYS_ADMIN).

## Production Ready?

No. Functional and tested interactively on a 5900X, but lacks the long-tail validation that the established schedulers (`scx_lavd`, `scx_bpfland`, `scx_flash`) have accumulated. Use it on a workstation, not a server.
