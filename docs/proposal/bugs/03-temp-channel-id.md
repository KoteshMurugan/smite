# Bug 3 — wrong channel_id used for interactive-tx messages

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Component    | `smite-scenarios` dual-funding scenario harness             |
| Severity     | Functional / coverage — wrong messages were being accepted by the target peer at all |
| Discovered by| Manual review while building the harness                    |
| Fix          | Upstream commit [`7c0cd4d`](../../../) — *fix: use temp_channel_id for all interactive-tx messages (Bug 3)* |

This one is from the smite repo itself, not from CLN — but it counts as
a project bug because the harness was silently sending messages with the
*derived* `channel_id` (computed from the funding outpoint) before the
funding tx existed, which made the target peer reject every
interactive-tx message until `tx_signatures`.

The fix routes all pre-`tx_signatures` interactive-tx messages through
`temp_channel_id` (the open_channel2 placeholder), matching BOLT 2.

I'm including it in the bug list because it's the kind of subtle BOLT
correctness bug that's exactly what differential / spec-driven fuzzing
is *supposed* to catch — and once it was fixed the fuzzer immediately
started reaching the deeper code paths where bugs 1 and 2 were waiting.
