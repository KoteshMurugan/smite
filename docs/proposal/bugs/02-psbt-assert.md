# Bug 2 — `assert()` on attacker-controlled libwally PSBT error

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Component    | `bitcoin/psbt.c`, downstream call-sites in `interactivetx.c` and `dualopend.c` |
| Severity     | Remote DoS — peer can crash dualopend with a single message |
| Discovered by| AFL++ Nyx, dual_funding scenario, ~6h after the first bug   |
| Patches      | [0002](../../../workloads/cln/patches/0002-psbt-no-assert-on-peer-input.patch) [0003](../../../workloads/cln/patches/0003-interactivetx-handle-null-output.patch) [0004](../../../workloads/cln/patches/0004-dualopend-handle-null-output.patch) |

## What the fuzzer hit

A `tx_add_output` whose `serial_id` ordered before any existing PSBT
output produced an `insert_at` index that libwally rejected with
`WALLY_EINVAL`. The CLN wrapper:

```c
wally_err = wally_psbt_add_tx_output_at(psbt, insert_at, 0, output);
assert(wally_err == WALLY_OK);
```

…turned that into `Assertion 'wally_err == WALLY_OK' failed`, which is
crashable from a single peer message — i.e. a remote DoS against the
dualopend subdaemon.

## Root cause

`psbt_add_output()` is a thin wrapper that asserts on every libwally
error. The wrapper has *two* call-sites that take peer-controlled
inputs:

1. `process_tx_add_output()` in `common/interactivetx.c` (peer's
   `tx_add_output` message).
2. `run_tx_interactive()` in `openingd/dualopend.c` (same path on the
   accepter side).

A third call-site adds the funding output we built ourselves — an
internal-invariant violation, not peer input.

The assert collapses all three cases into "abort". Peer-controlled
input must instead be reported as a protocol error so we send
`tx_abort`, not crash.

## Fix

Three commits, applied in order:

- **0002** — replace the `assert()` with a `return NULL`. This is the
  minimal change that lets callers distinguish error from success.
- **0003** — handle NULL in `process_tx_add_output()` by returning a
  protocol-error string (the existing error machinery already routes
  this back as `tx_abort`).
- **0004** — handle NULL in the two dualopend call-sites: peer-input
  path → `open_abort()`, internal funding-output path →
  `status_failed(STATUS_FAIL_INTERNAL_ERROR, …)`.

## Verification

- Replayed saved Nyx input against patched build → no crash, peer
  receives `tx_abort` with "Output rejected by PSBT".
- 12h post-patch run — assertion site no longer reachable from any
  saved queue input.

## Status

Patched in this branch. Plan during SoB:

- Open one upstream PR per logical change (or a single bundled PR if
  reviewers prefer).
- Add a regression scenario to the seed corpus that triggers the same
  insert-index pattern.
