# Proposed timeline (12 weeks)

Working assumption: full-time, 40h/week, with one weekly sync with mentors.

## Week 0 — Pre-program prep (already done)

- This branch — wire codecs, BOLT 3, IR ops, Executor, dual-funding
  scenario, Nyx Docker image, 2 bugs already triaged and patched.

## Weeks 1–2 — Land the existing CLN patches upstream

- Open one PR per patch on `ElementsProject/lightning`:
  0001 (talz), 0002 (psbt return-NULL), 0003 + 0004 (NULL handling).
- Add a deterministic regression scenario to the seed corpus for each.
- Document the bug + fix in `docs/proposal/bugs/`.

**Deliverable:** four merged or in-review PRs against CLN.

## Weeks 3–5 — Eclair / LDK / LND target parity

- Extend the dual-funding scenario to use the existing Eclair / LDK / LND
  targets via the per-impl bins already scaffolded in this branch.
- Reuse the same IR program — the whole point of smite-IR is that the
  generator is target-agnostic.
- Wire each impl into its existing fuzzing Dockerfile under `workloads/`.

**Deliverable:** `cargo run --bin {cln,eclair,ldk,lnd}_dual_funding` all
work end-to-end against a regtest bitcoind. AFL++ container builds for
each. At least one differential bug (impls disagree on the same input).

## Weeks 6–8 — Multi-week fuzzing campaign

- Run all four impls in parallel on the existing GCP VM
  (`smite-fuzzer`, `asia-south1-b`, n2-standard-32 or larger).
- Daily triage: every saved crash → minimised IR → bug report under
  `docs/proposal/bugs/` → upstream PR if confirmed.
- Coverage report per impl, published in the branch.

**Deliverable:** ≥3 bugs filed upstream (any impl), coverage HTML for
each impl checked in under `docs/proposal/coverage/`.

## Weeks 9–11 — Splice OR more bugs (mentor's call)

Two ways to spend the last sprint, decided with mentors at the week-8
sync:

**Option A — Splice scenarios.** BOLT 2 splice messages are the natural
follow-up: same interactive-tx machinery, different state. Add the wire
codecs, the IR ops, and a `splice` scenario alongside `dual_funding`.

**Option B — Bug push.** Use the campaign data to focus on the deepest
parts of the impls (commitment-tx update flows, on-chain handling) and
ship as many bug reports as possible.

**Deliverable:** either splice-aware fuzzing harness, or a documented
batch of upstream bug reports.

## Week 12 — Wrap-up

- Final coverage report.
- Project writeup.
- Hand-off doc so the next contributor can pick up the campaign without
  losing the queue / corpus.

## Risk register

| Risk | Mitigation |
|------|-----------|
| Upstream review latency on the CLN patches | Don't block on it — keep them as workload patches in the meantime, and use the gap weeks for Eclair / LDK / LND parity. |
| Eclair/LDK target parity is harder than expected (JVM / Rust async tests) | Two of the four impls already build today; even shipping two impls is enough to find differential bugs. |
| GCP costs | One n2-standard-32 VM at preemptible pricing is well under the SoB stipend. Already validated with the current campaign. |
| Bugs dry up after week 6 | The splice option (week 9–11) is exactly the contingency for that. |
