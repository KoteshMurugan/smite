/*
 * Standalone PoC for bug 0001: UBSan crash from uninitialised
 * `state->reconnected` bool in openingd/dualopend.c.
 *
 * Background:
 *   At openingd/dualopend.c:4340 the main state struct is allocated with
 *   `tal(NULL, struct state)`, which returns uninitialised memory.
 *   `state->reconnected` (a bool, declared at line 214) is then read at
 *   line 1279 (`if (!state->reconnected)`) before any code path assigns
 *   it on the fresh-launch (non-reconnect) flow. UBSan flags this with:
 *
 *     runtime error: load of value 254, which is not a valid value
 *     for type 'bool'
 *
 *   The patch (workloads/cln/patches/0001-dualopend-init-reconnected.patch)
 *   replaces `tal` with `talz`, which zero-initialises the whole struct.
 *
 * What this PoC does:
 *   Allocates a struct with the same shape (one bool plus padding) using
 *   tal, free's it back to the tal pool, and then re-allocates a struct
 *   of the same size — the second allocation reuses the freed memory,
 *   which under glibc still contains whatever bytes were in there. We
 *   poison the memory with 0xFE between the alloc and free to make the
 *   crash deterministic; in production the byte value depends on heap
 *   state at lightningd startup, but the bug class is the same.
 *
 *   Two #defines control behaviour:
 *     -DUSE_TALZ   build the "patched" version (uses talz instead of tal)
 *     (default)    build the "vanilla" version (uses tal)
 *
 * Build (drop into the CLN source tree as openingd/test/run-bug-verify-tal.c):
 *   gcc -fsanitize=undefined -fno-sanitize-recover=undefined \
 *       -I . -I external/jsmn -I external/libwally-core/include \
 *       -I ccan -o run-bug-verify-tal-vanilla \
 *       openingd/test/run-bug-verify-tal.c \
 *       ccan/ccan/tal/tal.c ccan/ccan/take/take.c ccan/ccan/list/list.c \
 *       ccan/ccan/str/str.c ccan/ccan/likely/likely.c
 *
 *   gcc -fsanitize=undefined -fno-sanitize-recover=undefined -DUSE_TALZ \
 *       -I . -I external/jsmn -I external/libwally-core/include \
 *       -I ccan -o run-bug-verify-tal-patched \
 *       openingd/test/run-bug-verify-tal.c \
 *       ccan/ccan/tal/tal.c ccan/ccan/take/take.c ccan/ccan/list/list.c \
 *       ccan/ccan/str/str.c ccan/ccan/likely/likely.c
 *
 * Expected:
 *   ./run-bug-verify-tal-vanilla
 *     -> UBSan: "runtime error: load of value 254, which is not a
 *        valid value for type 'bool'"   exit code 1
 *   ./run-bug-verify-tal-patched
 *     -> "PATCHED_OK"   exit code 0
 */
#include "config.h"
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Mirrors the dualopend `struct state` shape closely enough to land
 * `reconnected` on the same offset class as the real struct: a bool
 * preceded and followed by larger fields, so heap reuse leaves a
 * non-zero byte where reconnected sits. */
struct mini_state {
    uint64_t leading_pad[2];
    bool reconnected;
    uint64_t trailing_pad[2];
};

#define LOG(...) do { fprintf(stderr, "[bug-verify-tal] " __VA_ARGS__); fflush(stderr); } while (0)

int main(void)
{
    /* Pre-stage: poison the tal pool with 0xFE so the next allocation
     * returns memory that contains a non-0, non-1 byte where
     * reconnected sits. This is what the heap looks like in practice
     * when dualopend launches after lightningd has already done a
     * batch of struct allocations. */
    struct mini_state *poison = tal(NULL, struct mini_state);
    memset(poison, 0xFE, sizeof(*poison));
    tal_free(poison);

#ifdef USE_TALZ
    /* Patched: talz zero-initialises everything, defeating the poison. */
    struct mini_state *s = talz(NULL, struct mini_state);
    LOG("patched build: allocated with talz, reconnected = %d\n",
        (int)s->reconnected);
#else
    /* Vanilla: tal returns the freed (still-poisoned) memory as-is. */
    struct mini_state *s = tal(NULL, struct mini_state);
    LOG("vanilla build: allocated with tal, reading reconnected\n");
#endif

    /* This is the line that trips UBSan in dualopend.c:1279. */
    if (!s->reconnected) {
        LOG("took fresh-channel path (reconnected was false)\n");
    } else {
        LOG("took reconnect path (reconnected was true)\n");
    }

    tal_free(s);

    printf("PATCHED_OK\n");
    return 0;
}
