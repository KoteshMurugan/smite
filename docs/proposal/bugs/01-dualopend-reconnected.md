# Bug 1 — UBSan crash from uninitialised `state->reconnected`

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Component    | `openingd/dualopend.c` (CLN v25.12.1, dualopend subdaemon)  |
| Severity     | Crash (UBSan), reachable from a peer's first message        |
| Discovered by| AFL++ Nyx, dual_funding scenario, ~24h on n2-standard-32     |
| Patch        | [0001-dualopend-init-reconnected.patch](../../../workloads/cln/patches/0001-dualopend-init-reconnected.patch) |

## What the fuzzer hit

The CLN binary is built with `-fsanitize=address,undefined`. The fuzzer
sent an `open_channel2` followed by a normal interactive-tx exchange.
On the first message dualopend reads `state->reconnected` to decide
whether to expect a `channel_reestablish` instead. UBSan reported:

    runtime error: load of value 254, which is not a valid value for
                   type 'bool'
    SUMMARY: openingd/dualopend.c:... in main()

The crash handler shared library then reported the failure via Nyx and
the snapshot reset. Reproducible across multiple runs from the same
saved input.

## Root cause

In `main()` the central state struct is allocated with `tal()`:

```c
struct state *state = tal(NULL, struct state);
```

`tal()` returns *uninitialised* memory. Most fields end up assigned
before they are read, but `state->reconnected` only gets a value on the
reconnection path — on a fresh connection it is read while still
uninitialised. UBSan trips on the garbage byte.

## Fix

Switch to `talz()`, which zeroes the whole struct. Every other piece of
dualopend code already assumes integer-valued fields default to zero, so
this just makes the struct match the rest of the code's expectations.

```c
-	struct state *state = tal(NULL, struct state);
+	struct state *state = talz(NULL, struct state);
```

## Verification

- Saved Nyx queue input replays cleanly against patched build.
- Re-ran the dual-funding scenario for 12h after applying the patch — no
  more uninitialised-bool reports from this site.

## Status

Patched in this branch. Not yet upstream — plan is to open a small PR
on `ElementsProject/lightning` during week 1 of SoB.
