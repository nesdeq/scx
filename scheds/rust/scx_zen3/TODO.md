# scx_zen3 — TODO

Open issues and future work, in rough order of how much they would actually
move the needle. Status: implementation complete, not production-validated.

## Correctness / placement gaps

### Dispatch-path SMT stacking

`zen3_dispatch` pulls from the per-CCD `dsq_render` to *whichever* CPU on
that CCD wakes asking for work. That includes the SMT sibling of a CPU
already running a hot RENDER task. `select_cpu` is now SMT-aware (the
ladder prefers cross-CCD over sibling-stack), but the dispatch fallback
isn't.

Fix sketch:
- Push a `cpu_to_sibling[MAX_CPUS]` table into BPF rodata from `topo::probe`.
- In `zen3_dispatch`, before pulling RENDER from a per-CCD DSQ on a CPU
  whose sibling is currently running RENDER, return without pulling
  (let another CPU on the CCD claim it on the next dispatch tick).
- ~30 LOC of plumbing + a sibling read in the dispatch hot path.

### Warm-stick lacks sibling-busy check

`warm_stick` reattaches to `last_cpu` if it's idle within the L3 warm
window (100 ms). It doesn't check whether the SMT sibling is currently
running another hot thread. If yes, the L1/L2 isn't actually warm
(sibling evicted it) *and* the physical core's execution units are
already contended.

Fix sketch: with the sibling table from above, refuse the stick when
`game_mask_test(sibling_of(cpu))` is true. Falls through to the normal
placement ladder.

## Detection robustness

### Launcher-wrapped games show wrong "primary" tgid

When a game runs via Battle.net / Uplay / Funcom / Epic / EA App (Wine
.exe launcher → game .exe child), `Detection::game_tgid` lands on the
launcher because:
- launcher PID is lower (started first → wins `/proc` scan order),
- launcher's own .exe isn't in the blocklist.

The family BFS does pick up the real game as a descendant, so classification
is still correct. The visible-state symptoms are cosmetic:
- stats `game_tgid=` and the entry-log `name=Battle.net.exe` point at the
  wrong process.

Two fix options:

1. **Blocklist expansion** (~10 LOC). Add to `wine_exe_name_from_cmdline`:
   `battle.net.exe`, `agent.exe`, `ubisoftconnect.exe`, `upc.exe`,
   `galaxyclient.exe`, `eadesktop.exe`, `eabackgroundservice.exe`,
   `epicgameslauncher.exe`, `funcomlauncher.exe`. Stale by definition.
2. **CPU-time-based primary picker** (~40 LOC). Sample utime+stime per
   family tgid in the detect loop; the heaviest one is almost always the
   game in steady state. Robust across launchers without maintenance.

### Steam env accepts `SteamGameId=0`

`has_steam_env` matches `SteamGameId=` with `len > 12`, which catches
`SteamGameId=0` set by Steam's own UI processes. Same wrong-primary
outcome as launcher case.

Fix: reject `SteamGameId=0` explicitly. One-line gate in
`detect.rs::has_steam_env`.

## Hardware validation

Validated interactively on a 5900X (Vermeer, dual-CCD, 12c/24t, non-X3D).
The following paths exist in code but have not been exercised:

- **5800X3D**: X3D detection (L3 > 64 MiB) → `enable_cpufreq = 0`. Need to
  confirm the cpuperf skip actually applies and that the L3 detection
  fires correctly under k10temp/sysfs variations.
- **5600X / 5700X**: single-CCD parts. `nr_ccds == 1` short-circuits
  `other_ccd()`; HOG/BG anti-affinity degenerates to "same CCD, reverse
  prefcore." Worth confirming HOG doesn't starve render.
- **5950X**: dual-CCD with 16 cores. Same logical shape as 5900X but more
  family workers may saturate one CCD; the cross-CCD spill ladder gets
  exercised harder.
- **Cezanne (5700G / 5600G)**: single-CCX integrated graphics. Unclear
  whether the iGPU compositor co-scheduling assumption holds.

## Stress / long-tail

- Scheduler-timeout recovery: `timeout_ms = 5000`. Inject deliberate hangs
  (long verifier-allowed busy loops) and confirm `uei_report` cleanly
  detaches.
- cgroup-pinned games (Flatpak Steam, scope-isolated Proton sessions).
  Verify family BFS sees descendants across the cgroup boundary; verify
  CPUPERF nudging fires for tasks in restricted cpusets.
- Anti-cheat under load: EAC / BattlEye services classified to HOG and
  exiled to non-game CCD. Confirm no false-positive flags from the
  anti-cheat itself.
- Long-running session (8h+): check for map fragmentation in
  `game_family_pids` and `anticheat_pids` after thousands of process
  spawn/exits.

## Tooling / observability

- **`STAT_RECLASS_EVENTS`** is in JSON stats but not the human-readable
  ticker line. Add to `Metrics::format` if it becomes a useful signal
  during gaming-session debugging.
- **Render-thread identification in stats**: currently we don't surface
  which thread the scheduler considers the renderer. Could expose
  `last_promoted_tid` via the bss → stats path for diagnostic visibility
  (but only if the BPF side stays write-once-per-promotion to avoid hot
  path churn).
- **Scheduler-mode transitions**: log the *first* render dispatch after
  entering GAMING mode (verifies the family pipeline lit up correctly).

## Won't-do (decided against, documented for posterity)

- **Adaptive frame budget**: deleted. The only consumer (`render_spill_allowed`)
  was structurally redundant after the SMT-aware placement ladder. See
  earlier commit history.
- **EDID / panel-refresh probing**: deleted. Wrong signal for VRR; says
  nothing about which output the game presents to.
- **Thermal-aware scheduling reactions**: tdie polling existed only to feed
  a dead BPF map field. Removed. Stats display still reads k10temp directly
  if needed (currently not displayed; `--stats` shows class counters only).
- **PB2 settle (`pb2_settle_ns`)**: deleted. Only fired in RENDER step 1;
  during gameplay (when it would matter), the game CCD is always busy and
  the gate is a no-op. The placement ladder gives the structural answer.
- **Always-on game mode**: rejected. HOG anti-affinity + 25% quota would
  throttle non-game compute workloads (compile, encode) to a quarter of
  one CCD even when no game is running. The `if (is_gaming)` mode gate
  exists precisely to protect daily-driver throughput.
