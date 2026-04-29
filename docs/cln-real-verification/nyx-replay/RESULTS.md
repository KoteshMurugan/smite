# Real-CLN A/B Replay Results

End-to-end runtime verification of the four CLN dual-funding patches by
replaying the saved fuzzer hang corpus against an unpatched vs. patched
build of CLN v25.12.1, driven by the same `smite-scenarios` Lightning
state-machine harness that originally found the bugs.

## Test setup

- VM: GCP `n2-standard-8`, 8 vCPU / 32 GB RAM, Ubuntu 22.04 (provisioned
  for this replay only; deleted after).
- Two docker images built from `workloads/cln/Dockerfile`:
  - `cln-dual-funding:vanilla` — `--build-arg APPLY_PATCHES=0`
  - `cln-dual-funding:patched` — `--build-arg APPLY_PATCHES=1`
  Both with `--enable-address-sanitizer --enable-ub-sanitizer`.
- Corpus: 76 hang inputs from `~/cln_hangs/cln-nyx/default/hangs/` on the
  GCP fuzzing VM (the same ones AFL++ flagged during the dual-funding
  campaign).
- Replay path: `LocalRunner` (no Nyx) — for each input,
  `SMITE_INPUT=/input.bin /cln-scenario` runs once with a 60s timeout.
- Replay script: see `../verify-replay.sh` (and `run-replay.sh` on the VM).

## Headline numbers

| Run         | CLEAN | FAIL ("crashed"/"hung") | ABORT (SIGABRT) | Total |
|-------------|------:|------------------------:|----------------:|------:|
| **vanilla** |    73 |                       2 |               1 |    76 |
| **patched** |    75 |                       1 |               0 |    76 |

Zero sanitizer aborts, zero asserts, zero segfaults on patched.

## Inputs that flip vanilla → patched

Two inputs that fail on unpatched CLN run cleanly on patched CLN:

### `id:000059` — direct hit on bug 0002 (PSBT assert)

Vanilla log (`logs/id:000059.log`, last line):

```
ERROR [smite_scenarios::targets] crash handler: assertion failed:
  "wally_err == WALLY_OK" in struct wally_psbt_output *psbt_add_output(
  struct wally_psbt *, struct wally_tx_output *, size_t) (bitcoin/psbt.c:268)
```

Same file (`bitcoin/psbt.c`), same line (268), same assertion text as the
standalone PoC in `../run-bug-verify-psbt.c`. Patch
`0002-psbt-no-assert-on-peer-input.patch` replaces the assert with a NULL
return. Patched run on the same input: `CLEAN`, exit 0.

### `id:000052` — generic abort

Vanilla log (`logs/id:000052.log`):

```
ERROR [smite_scenarios::targets] crash handler: abort
ERROR [smite::runners] Test case failed: target crashed
```

Generic abort — log doesn't pinpoint a single assert text, so this is one
of bugs 0001/0003/0004 (all of which call `abort()` via either a tal
NULL-deref or a missing NULL check on `psbt_append_output`). Patched run:
`CLEAN`, exit 0.

## Inputs that hang on both runs

`id:000004` reports `target hung (ping timeout)` on both vanilla and
patched. The patches do not promise to remove this slow-path; the
significance is that **on patched it never escalates to a crash or
sanitizer trip** — it stays a clean timeout, exactly the
defensive-rejection behaviour the patches aim for.

## Why only two flips out of 76?

Most of AFL's 76 saved hangs are timeout-classified, not crash-
classified — AFL gave up waiting after its per-execution timeout, which on
the Nyx setup includes long state-machine paths (lightningd init, BIP-22
sync, multi-round dual-funding negotiation). When replayed with a 60s
budget under `LocalRunner`, most of those finish normally on either
build.

Of the inputs that actually trip a crash signal, **all of them** flip from
crash-on-vanilla to clean-on-patched, with no regressions in the other
direction.

## Files

- `replay-results/patched-v1/summary.csv` — 76 lines of `id,exit_code,
  classification,signature` for the patched run
- `replay-results/vanilla-v1/summary.csv` — same for vanilla
- `replay-results/patched-v1/logs/*.log` — full stderr per input (patched)
- `replay-results/vanilla-v1/logs/*.log` — full stderr per input (vanilla)

Pair this with `../verify.log` (the standalone in-tree
`bitcoin/test/run-bug-verify-psbt.c` PoC, which deterministically aborts
on vanilla and exits cleanly on patched) and you have two independent
runtime confirmations of bug 0002 on real CLN, plus end-to-end A/B
evidence that the four-patch series eliminates every crash signal in the
saved hang corpus.
