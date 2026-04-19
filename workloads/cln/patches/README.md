# CLN dual-funding patches

Bug fixes discovered by the dual-funding fuzzing harness in this repo,
applied on top of CLN v25.12.1. The patches are stored as standalone
files so they can be applied in the Dockerfile (or by hand for local
reproduction) without forking the upstream tree.

| Patch | Severity | Subdaemon  | Summary                                                              |
|-------|----------|------------|----------------------------------------------------------------------|
| 0001  | Crash    | dualopend  | UBSan: uninitialised `state->reconnected` bool                        |
| 0002  | DoS      | bitcoin    | `assert()` on attacker-controlled `wally_psbt_add_tx_output_at` error |
| 0003  | NULL     | interactivetx | Handle NULL from `psbt_append_output` in tx_add_output path         |
| 0004  | NULL     | dualopend  | Handle NULL from `psbt_append_output` in user + funding output paths  |

Apply order matters: 0002 introduces NULL returns that 0003 and 0004
handle. Applied in-tree with `patch -p1 -F3` from the CLN source root.

Both crashes were reproduced from saved Nyx queue inputs against the
unpatched build, then verified to no longer trigger after rebuilding the
fuzz container with these patches applied.
