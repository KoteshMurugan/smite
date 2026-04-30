/*
 * In-tree PoC for bug 0001: UBSan crash from uninitialised
 * `state->reconnected` bool in openingd/dualopend.c (CLN v25.12.1).
 *
 * --- The bug, in three real source lines --------------------------------
 *
 *   openingd/dualopend.c:154    struct state { ... bool reconnected; ... };
 *   openingd/dualopend.c:213-214    /​* Were we reconnected at start? *​/
 *                                 bool reconnected;
 *   openingd/dualopend.c:1283   if (!state->reconnected)            <-- read site
 *                                   open_err_fatal(state, "Sent commit signed
 *                                                  out of turn (not reconnect)");
 *   openingd/dualopend.c:4340   struct state *state = tal(NULL, struct state);
 *                                                       ^^^^^^^^^^^^^^^^^^^^^^^
 *                                                       returns uninit memory
 *
 * `tal()` (ccan/tal/tal.c) returns uninitialised heap. On the fresh-channel
 * path the code at 1283 reads `state->reconnected` before any branch has
 * written it. UBSan rejects bool loads whose byte is not 0 or 1, so when
 * the heap byte at that offset happens to be e.g. 0xFE the program traps
 * with `runtime error: load of value 254, which is not a valid value for
 * type 'bool'`.
 *
 * The patch (workloads/cln/patches/0001-dualopend-init-reconnected.patch)
 * is a one-line change at openingd/dualopend.c:4340 — `tal(...)` becomes
 * `talz(...)`, which zero-fills the whole struct.
 *
 * --- Why this PoC uses a faithful struct copy ---------------------------
 *
 * `struct state` is file-static inside dualopend.c (no header), and pulling
 * in the full file requires mocking dozens of CLN symbols. Instead this
 * PoC copies the real struct verbatim from openingd/dualopend.c:154-227,
 * with field types replaced by same-sized opaque stand-ins where needed.
 * What matters for the bug is the allocator (real ccan/tal vs talz), not
 * the bytes that follow `reconnected`, so the trailing fields are dropped
 * and the leading layout is preserved exactly to mirror real production
 * field offsets.
 *
 * --- Why we poison the tal pool ----------------------------------------
 *
 * In production the bug fires only when the heap byte at the offset of
 * `reconnected` happens to be non-0/1 — depends on what lightningd has
 * allocated and freed before dualopend launches. To make the PoC
 * deterministic this code allocates a struct via `tal`, memsets it to
 * 0xFE (the canonical "uninit" debug poison), frees it back to the tal
 * pool, then re-allocates: under glibc the second tal() reuses the freed
 * memory verbatim, giving us a controlled non-bool byte at the right
 * offset. With `-DUSE_TALZ` the second alloc uses `talz`, which zero-fills
 * and defeats the poison — that is exactly what the patch does.
 *
 * --- Drop into the CLN source tree -------------------------------------
 *
 * Place at bitcoin/test/run-bug-verify-tal.c (alongside run-bug-verify-psbt.c).
 * CLN's Makefile auto-picks up bitcoin/test/run-*.c.
 *
 * Build (vanilla, must trip UBSan):
 *   make bitcoin/test/run-bug-verify-tal
 *
 * Build (patched, must exit cleanly):
 *   make CFLAGS="-DUSE_TALZ" bitcoin/test/run-bug-verify-tal
 *
 * Manual build (if not using CLN's Makefile):
 *   gcc -fsanitize=undefined -fno-sanitize-recover=undefined \
 *       -I . -I external/jsmn -I external/libwally-core/include -I ccan \
 *       -o run-bug-verify-tal-vanilla \
 *       bitcoin/test/run-bug-verify-tal.c \
 *       ccan/ccan/tal/tal.c ccan/ccan/take/take.c ccan/ccan/list/list.c \
 *       ccan/ccan/str/str.c ccan/ccan/likely/likely.c
 *
 * Expected:
 *   ./run-bug-verify-tal-vanilla
 *     -> "runtime error: load of value 254, which is not a valid value
 *         for type 'bool'"   exit code 1
 *   ./run-bug-verify-tal-patched
 *     -> "PATCHED_OK"   exit code 0
 */
#include "config.h"
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* CLN-style typedefs that the real struct uses. */
typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* NUM_SIDES is 2 in CLN (LOCAL, REMOTE). */
#define NUM_SIDES 2

/* Same-size opaque stand-ins for the real struct's compound fields.
 * We never read or write through them — they only need to occupy the
 * same number of bytes as the real types so that `reconnected` lands
 * at the same offset as in the real struct. Sizes were chosen to match
 * the real CLN x86_64 build of v25.12.1. */
struct opaque_pps          { void *p; };
struct opaque_amount_msat  { u64 v; };
struct opaque_amount_sat   { u64 v; };
struct opaque_basepoints   { u8 b[33 * 5]; };
struct opaque_pubkey       { u8 b[33]; };
struct opaque_channel_id   { u8 b[32]; };
struct opaque_channel      { void *p; };
struct opaque_channel_type { void *p; };
struct opaque_feature_set  { void *p; };

/* Faithful copy of openingd/dualopend.c:154-216. Trailing fields after
 * `reconnected` are omitted because they don't influence its offset.
 * If you compare this to dualopend.c the only differences are the
 * opaque_* type names (size-equivalent) and the truncation. */
struct state {
    struct opaque_pps          *pps;
    bool                        developer;
    u8                         *their_features;
    u32                         minimum_depth;
    struct opaque_amount_msat   min_effective_htlc_capacity;
    u32                         max_to_self_delay;
    struct opaque_basepoints    our_points;
    struct opaque_pubkey        our_funding_pubkey;
    struct opaque_pubkey        their_funding_pubkey;
    struct opaque_basepoints    their_points;
    struct opaque_pubkey        first_per_commitment_point[NUM_SIDES];
    struct opaque_pubkey        second_per_commitment_point[NUM_SIDES];
    struct opaque_channel_id    channel_id;
    u8                          channel_flags;
    int                         our_role;
    u32                         feerate_per_kw_commitment;
    u8                         *upfront_shutdown_script[NUM_SIDES];
    u32                        *local_upfront_shutdown_wallet_index;
    struct opaque_channel      *channel;
    struct opaque_channel_type *channel_type;
    struct opaque_feature_set  *our_features;
    bool                        channel_ready[NUM_SIDES];
    bool                        shutdown_sent[NUM_SIDES];
    bool                        reconnected;             /* <-- the bug */
    /* trailing fields omitted (don't affect offset of `reconnected`) */
};

#define LOG(...) do { fprintf(stderr, "[bug-verify-tal] " __VA_ARGS__); fflush(stderr); } while (0)

int main(void)
{
    /* Pre-stage: poison the tal pool so the next allocation returns
     * memory containing a non-0, non-1 byte where reconnected sits.
     * This deterministically reproduces the heap state that the
     * AFL+Nyx campaign hit non-deterministically. */
    struct state *poison = tal(NULL, struct state);
    memset(poison, 0xFE, sizeof(*poison));
    tal_free(poison);

#ifdef USE_TALZ
    /* Patched (workloads/cln/patches/0001-dualopend-init-reconnected.patch):
     * talz zero-fills the whole struct, defeating the poison.
     * This is the exact change the patch makes at dualopend.c:4340. */
    struct state *state = talz(NULL, struct state);
    LOG("patched build: allocated with talz, reconnected = %d\n",
        (int)state->reconnected);
#else
    /* Vanilla: this is the literal allocation at dualopend.c:4340. */
    struct state *state = tal(NULL, struct state);
    LOG("vanilla build: allocated with tal, reading reconnected\n");
#endif

    /* This is the literal read at dualopend.c:1283 inside
     * handle_commit_signed(). UBSan traps here on the vanilla build
     * if the byte is not 0/1. */
    if (!state->reconnected) {
        LOG("took fresh-channel path (reconnected was false)\n");
    } else {
        LOG("took reconnect path (reconnected was true)\n");
    }

    tal_free(state);

    printf("PATCHED_OK\n");
    return 0;
}
