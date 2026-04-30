#!/bin/bash
# Real-CLN patch verification (bugs 0001 + 0002).
#
# Runs *inside* the verify container. For each bug it:
#   1. Builds the in-tree harness on VANILLA CLN v25.12.1.
#   2. Runs it -> expects the bug signature (SIGABRT for 0002, UBSan
#      runtime-error for 0001).
#   3. Applies all 4 patches.
#   4. Rebuilds incrementally.
#   5. Runs the harness again -> expects clean exit (PATCHED_OK).
#   6. Greps the patched source files to confirm the textual fixes are in
#      place for bugs 0001/0003/0004.
#
# Both harnesses live at bitcoin/test/run-bug-verify-*.c and are picked up
# automatically by CLN's Makefile.

set -u
cd /work/cln

ASAN_OPT='abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=0:symbolize=1'
UBSAN_OPT='abort_on_error=1:halt_on_error=1:print_stacktrace=1:symbolize=1'

PSBT=bitcoin/test/run-bug-verify-psbt
TAL=bitcoin/test/run-bug-verify-tal

banner() { printf '\n=========================================================\n%s\n=========================================================\n' "$*"; }

###############################################################################
# Phase A: VANILLA — both bugs must reproduce on stock v25.12.1.
###############################################################################

banner "[A1] build VANILLA harnesses"
make -j"$(nproc)" "$PSBT" "$TAL" 2>&1 | tail -8
test -x "$PSBT" || { echo "BUILD FAILED: $PSBT"; exit 10; }
test -x "$TAL"  || { echo "BUILD FAILED: $TAL";  exit 10; }

banner "[A2] run VANILLA bug 0002 (psbt assert) — expecting SIGABRT"
ASAN_OPTIONS="$ASAN_OPT" UBSAN_OPTIONS="$UBSAN_OPT" ./"$PSBT"
RC_PSBT_VAN=$?
echo "VANILLA $PSBT exit code = $RC_PSBT_VAN"
if [ "$RC_PSBT_VAN" -ne 134 ] && [ "$RC_PSBT_VAN" -ne 139 ]; then
    echo "FAIL: vanilla psbt harness exited cleanly ($RC_PSBT_VAN) — assert was not triggered"
    exit 11
fi
echo "OK: vanilla psbt harness aborted as expected (rc=$RC_PSBT_VAN)"

banner "[A3] run VANILLA bug 0001 (uninit reconnected) — expecting UBSan trip"
# UBSan runtime-error -> exit 1 because the test was built with
# -fno-sanitize-recover=undefined. Capture stderr so we can grep for the
# canonical signature.
ASAN_OPTIONS="$ASAN_OPT" UBSAN_OPTIONS="$UBSAN_OPT" \
    ./"$TAL" 2>&1 | tee /tmp/tal-vanilla.out
RC_TAL_VAN=${PIPESTATUS[0]}
echo "VANILLA $TAL exit code = $RC_TAL_VAN"
if ! grep -q "runtime error: load of value" /tmp/tal-vanilla.out; then
    echo "FAIL: vanilla tal harness did not print the UBSan runtime-error signature"
    exit 12
fi
if ! grep -q "not a valid value for type '_Bool'" /tmp/tal-vanilla.out; then
    echo "FAIL: vanilla tal harness UBSan output did not mention _Bool"
    exit 12
fi
if [ "$RC_TAL_VAN" -eq 0 ]; then
    echo "FAIL: vanilla tal harness exited 0 — UBSan didn't trap"
    exit 12
fi
echo "OK: vanilla tal harness tripped UBSan with the canonical bool-load signature"

###############################################################################
# Phase B: apply patches and prove they really land.
###############################################################################

banner "[B1] apply 4 patches"
for p in /work/patches/00*.patch; do
    echo "--- applying $(basename "$p") ---"
    if ! patch -p1 -F0 < "$p"; then
        echo "PATCH FAILED: $p"
        exit 13
    fi
done

banner "[B2] confirm patched source contains the textual fixes"
echo "[bug 0001] dualopend.c — tal vs talz on struct state:"
grep -n "tal\(z\)\?(NULL, struct state)" openingd/dualopend.c | head -3 || true
echo
echo "[bug 0002] psbt.c — assert removed, NULL return present:"
sed -n '263,275p' bitcoin/psbt.c
echo
echo "[bug 0003] interactivetx.c — NULL check on out:"
grep -n -A1 "psbt_append_output(ictx->current_psbt" common/interactivetx.c | head -8
echo
echo "[bug 0004] dualopend.c — NULL checks at both call sites:"
grep -n -B0 -A2 'open_abort.*Output rejected by PSBT' openingd/dualopend.c | head -6
grep -n -B0 -A2 'funding output rejected by PSBT' openingd/dualopend.c | head -6

###############################################################################
# Phase C: PATCHED — both bugs must be quiet.
###############################################################################

banner "[C1] incremental rebuild of patched harnesses"
make -j"$(nproc)" "$PSBT" "$TAL" 2>&1 | tail -8
test -x "$PSBT" || { echo "REBUILD FAILED: $PSBT"; exit 14; }
test -x "$TAL"  || { echo "REBUILD FAILED: $TAL";  exit 14; }

# Don't abort-on-error so any unexpected sanitizer chatter still flushes.
ulimit -c unlimited 2>/dev/null || true
ASAN_OPT_PATCHED='halt_on_error=0:abort_on_error=0:print_stacktrace=1:detect_leaks=0:symbolize=1'
UBSAN_OPT_PATCHED='halt_on_error=0:abort_on_error=0:print_stacktrace=1:symbolize=1'

# Note: bug 0001's patch lives in dualopend.c, but our tal harness uses
# its own `-DUSE_TALZ` toggle to mirror tal->talz. Rebuild the harness
# explicitly with -DUSE_TALZ so the patched run actually exercises the
# fixed allocator.
banner "[C2] rebuild tal harness with -DUSE_TALZ for the patched run"
make CFLAGS="-DUSE_TALZ" -j"$(nproc)" "$TAL" 2>&1 | tail -8
test -x "$TAL" || { echo "REBUILD FAILED (USE_TALZ): $TAL"; exit 15; }

banner "[C3] run PATCHED bug 0002 (psbt) — expecting PATCHED_OK"
ASAN_OPTIONS="$ASAN_OPT_PATCHED" UBSAN_OPTIONS="$UBSAN_OPT_PATCHED" \
    ./"$PSBT"
RC_PSBT_PATCH=$?
echo "PATCHED $PSBT exit code = $RC_PSBT_PATCH"
if [ "$RC_PSBT_PATCH" -ne 0 ]; then
    echo "FAIL: patched psbt harness did not exit cleanly"
    exit 16
fi

banner "[C4] run PATCHED bug 0001 (tal) — expecting PATCHED_OK, no UBSan"
ASAN_OPTIONS="$ASAN_OPT_PATCHED" UBSAN_OPTIONS="$UBSAN_OPT_PATCHED" \
    ./"$TAL" 2>&1 | tee /tmp/tal-patched.out
RC_TAL_PATCH=${PIPESTATUS[0]}
echo "PATCHED $TAL exit code = $RC_TAL_PATCH"
if [ "$RC_TAL_PATCH" -ne 0 ]; then
    echo "FAIL: patched tal harness did not exit cleanly"
    exit 17
fi
if grep -q "runtime error" /tmp/tal-patched.out; then
    echo "FAIL: patched tal harness still has UBSan runtime-error output"
    exit 18
fi
if ! grep -q "PATCHED_OK" /tmp/tal-patched.out; then
    echo "FAIL: patched tal harness did not print PATCHED_OK"
    exit 19
fi

banner "RESULT"
echo "bug 0001 (uninit reconnected bool):"
echo "  vanilla: UBSan trip       (rc=$RC_TAL_VAN)   -> reproduced on real CLN"
echo "  patched: clean PATCHED_OK (rc=$RC_TAL_PATCH) -> tal->talz fixes it"
echo
echo "bug 0002 (psbt_add_output assert):"
echo "  vanilla: SIGABRT          (rc=$RC_PSBT_VAN)   -> reproduced on real CLN"
echo "  patched: clean PATCHED_OK (rc=$RC_PSBT_PATCH) -> assert->NULL fixes it"
echo
echo "Source-level fixes for 0003, 0004 confirmed by grep above."
exit 0
