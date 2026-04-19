# Summer of Bitcoin 2026 — Interactive Transaction (Dual Funding) Fuzzing

**Applicant:** Kotesh Murugan (`KoteshMurugan`, koteshlost@gmail.com)
**Project:** smite — differential & coverage-guided fuzzer for Lightning
implementations
**Mentor org:** smite

This branch (`dual-funding`) is a portfolio drop demonstrating the work I
have already completed against the Summer of Bitcoin proposal scope, and
the plan for the rest of the program.

## What's in this branch

| Layer            | Status     | Lines  | Where                                                   |
|------------------|------------|--------|---------------------------------------------------------|
| BOLT 2 wire codecs (interactive-tx, RBF, close, reestablish) | done | ~1.5k | [smite/src/bolt/](../../smite/src/bolt/)               |
| BOLT 3 commitment-tx + BIP 143 sighash | done | ~700  | [smite/src/bolt3.rs](../../smite/src/bolt3.rs)          |
| smite-IR types + operations (16 new ops) | done | ~700  | [smite-ir/src/operation.rs](../../smite-ir/src/operation.rs) |
| smite-IR Executor (drives a target with an IR program) | done | ~1.7k | [smite-ir/src/executor.rs](../../smite-ir/src/executor.rs)   |
| InteractiveTxGenerator (dual-funding-aware random programs) | done | ~250  | [smite-ir/src/generators.rs](../../smite-ir/src/generators.rs) |
| Dual-funding scenario + bitcoind funding-utxo provisioning | done | ~700  | [smite-scenarios/src/scenarios/dual_funding.rs](../../smite-scenarios/src/scenarios/dual_funding.rs) |
| Hand-crafted seed-corpus generator (RBF, abort, asymmetric, …) | done | ~1.4k | [smite-scenarios/src/bin/gen_dual_funding_corpus.rs](../../smite-scenarios/src/bin/gen_dual_funding_corpus.rs) |
| CLN target wired up end-to-end with Nyx snapshot fuzzing | done |    -   | [smite-scenarios/src/targets/cln.rs](../../smite-scenarios/src/targets/cln.rs), [workloads/cln/Dockerfile](../../workloads/cln/Dockerfile) |
| Eclair / LDK / LND per-impl entry points | scaffolded | ~50 | [smite-scenarios/src/bin/](../../smite-scenarios/src/bin/) |
| Bug fixes pushed back to CLN as patches | 4 patches | ~150 | [workloads/cln/patches/](../../workloads/cln/patches/) |

Total diff vs. upstream `master`: **~7k lines across 11 atomic commits.**

## Bugs already found

While iterating on the harness I let it run against an unpatched
`v25.12.1` build of CLN on a GCP VM with AFL++ Nyx. Three bugs surfaced
within the first ~24h of fuzzing, two of them previously unknown:

| # | Severity | Component | Status |
|---|----------|-----------|--------|
| 1 | UBSan crash | `dualopend` uninit `state->reconnected` | Patched ([0001](../../workloads/cln/patches/0001-dualopend-init-reconnected.patch)) — see [bug 1 report](bugs/01-dualopend-reconnected.md) |
| 2 | DoS assert | `bitcoin/psbt.c` assert on attacker input | Patched ([0002–0004](../../workloads/cln/patches/)) — see [bug 2 report](bugs/02-psbt-assert.md) |
| 3 | Protocol bug | wrong channel_id in interactive-tx messages | Already fixed by upstream commit [`7c0cd4d`](../../) — discovered independently while building the harness |

The patches still need upstream review; the plan during SoB is to land
them and add regression scenarios to the seed corpus.

## Why this branch is structured this way

The brief asks the candidate to *prove* they can ship the work, not just
list what they would do. Each commit on this branch is buildable in
isolation and answers a different "can you do X?" question:

- **Wire codecs commit** — can you read BOLTs and write spec-correct
  serializers with roundtrip tests?
- **bolt3 commit** — do you understand BIP 143 and BOLT 3 commitment
  transactions, well enough to *sign* them?
- **smite-IR ops commit** — can you extend an existing IR safely (type
  system stays sound, Operation enum stays exhaustive)?
- **Executor commit** — can you wire an IR up to a real target without
  knowing in advance which messages the harness will send?
- **Scenario / generator commits** — can you turn the BOLT 2
  state machine into something an AFL++ mutator can drive?
- **Patches commit** — when you find a real bug, can you fix it in C and
  get the fix into a real subdaemon?

## What I will deliver during the program

Detailed estimate: see [TIMELINE.md](TIMELINE.md). One-line summary:

> Land the four CLN patches, finish Eclair / LDK / LND parity for the
> dual-funding scenario, run a multi-week fuzzing campaign on a single
> GCP VM, and either ship splice-funding scenarios or land 3 more bugs
> — whichever the mentors prefer.
