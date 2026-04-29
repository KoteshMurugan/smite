# Ping-timeout (`id:000004`) — root cause

The 76-input replay reported `id:000004` as `target hung (ping timeout)`
on **both** vanilla and patched CLN builds. This file documents what
the input actually does and where the hang sits.

## Where the timeout fires

`smite-scenarios/src/scenarios/dual_funding.rs:214-220` runs `ping_pong`
*after* the IR program finishes, as a synchronization barrier. If pong
doesn't arrive within the timeout, the runner returns
`Fail("target hung (ping timeout)")`. So the "hang" is detected on the
**Smite side**, after CLN has already processed the input.

## What the input does

`dump_program /tmp/id_000004.bin` shows 68 instructions. The relevant
section, after the dual-funding negotiation finishes:

```
v51 = BuildTxComplete(v35)
SendMessage(v51)
RecvTxComplete()
v54 = BuildSignedCommitmentSigned(v35, v0, v36, v3, v5, v7, v31, v32,
                                   v33, v34, v22, v17, v19, v18, v37)
SendMessage(v54)
v56 = RecvTxSignatures()
v57 = ComputeFundingWitness()
v58 = BuildTxSignatures(v35, v56, v57)
SendMessage(v41)             <-- WRONG: v41 is BuildTxAddOutput, not v58
v60 = LoadBytes(0x0014...)
v61 = BuildShutdown(v35, v60)
SendMessage(v61)
...
```

`v41` is `BuildTxAddOutput` from earlier in the program; `v58` is the
freshly built `BuildTxSignatures`. The mutation re-bound the
`SendMessage` to point at the wrong instruction value, so instead of
sending `tx_signatures` after receiving the peer's `tx_signatures`, the
fuzzer re-sends a stale `tx_add_output`.

This is exactly the kind of "well-formed Program, semantically wrong
order" that AFL's havoc mutator produces by flipping a serial-id byte.

## Why CLN doesn't pong

After the dual-funding negotiation has reached the
commitment_signed / tx_signatures phase, dualopend has already handed
the channel off; receiving a `tx_add_output` at that point is a
protocol violation. CLN logs a warning and closes the BOLT-08 noise
connection on its side. After the close, smite's `ping` write succeeds
into the kernel socket buffer, but no `pong` ever comes back, so the
read times out and we report "target hung (ping timeout)".

## Is this a bug?

- **In CLN**: closing the connection on a protocol violation is the
  intended behaviour, not a bug. The patches in this series don't
  change that path.
- **In Smite**: the runner conflates "peer disconnected after our
  bad message" with "peer is hung". Both produce the same symptom
  (no pong received), but they are different conditions. A small
  improvement would be to call `check_alive` before deciding it's a
  hang, or to detect a closed socket via `recv() == 0` and report
  `target rejected our message` instead of `target hung`.

## Why this matters for the patch series

The four patches address `assert()` and NULL-deref crashes — they make
CLN tolerant of *adversarial input bytes*. They do **not** promise
to keep the connection alive across every wrong-order message
sequence. `id:000004` is in the second category, and it stays a
clean `target hung` (no SIGABRT, no sanitizer trip) on both builds —
which is the defensive-rejection behaviour the patches aim for, just
imperfectly diagnosed by the harness.

## Reproducing

The 514-byte input is committed at
`docs/cln-real-verification/key-evidence/` (see the existing
A/B-replay key-evidence directory; `id:000004` is also among the 76
files in `nyx-replay/replay-results/*/logs/`).

```bash
# inspect the program
target/release/dump_program docs/cln-real-verification/key-evidence/id_000004.bin

# replay against patched CLN
docker run --rm \
  -v $(pwd)/docs/cln-real-verification/key-evidence/id_000004.bin:/input.bin:ro \
  -e SMITE_INPUT=/input.bin -e RUST_LOG=info \
  --entrypoint /cln-scenario cln-dual-funding:patched
# expected: "Test case failed: target hung (ping timeout)"
```
