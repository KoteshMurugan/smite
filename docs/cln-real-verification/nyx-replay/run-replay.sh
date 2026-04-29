#!/bin/bash
# Replay all hangs against a CLN docker image. Classifies each input as:
#   CLEAN   - exit 0
#   FAIL    - non-zero exit, no asan/ubsan signature
#   ABORT   - exit 134 (SIGABRT) or assert-text in log
#   SEGV    - exit 139
#   ASAN    - asan signature in stderr
#   UBSAN   - ubsan signature in stderr
#   TIMEOUT - hit 60s docker timeout
#
# Usage: ./run-replay.sh <image-tag> <label>
# Output: ~/replay-results/<label>/summary.csv + per-input logs/
set -u
IMG="${1:?usage: $0 <image-tag> <label>}"
LABEL="${2:?label}"
HANGS=/home/methonicmurugan/cln_hangs/hangs
OUT=/home/methonicmurugan/replay-results/$LABEL
mkdir -p "$OUT/logs"
SUMMARY="$OUT/summary.csv"
echo 'input,exit_code,classification,signature' > "$SUMMARY"

count=0
for input in "$HANGS"/id:*; do
  count=$((count+1))
  name=$(basename "$input")
  short=$(echo "$name" | cut -d, -f1)
  log="$OUT/logs/${short}.log"

  # AFL filenames have colons -> docker -v gets confused; copy first.
  cp "$input" /tmp/replay-input.bin

  set +e
  sudo timeout 60 docker run --rm \
    -v /tmp/replay-input.bin:/input.bin:ro \
    -e SMITE_INPUT=/input.bin \
    -e RUST_LOG=info \
    -e ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=0:symbolize=1 \
    -e UBSAN_OPTIONS=abort_on_error=1:halt_on_error=1:print_stacktrace=1:symbolize=1 \
    --entrypoint /cln-scenario \
    "$IMG" >"$log" 2>&1
  rc=$?
  set -e

  cls='OTHER'; sig=''
  if grep -qE 'AddressSanitizer|ASAN' "$log" 2>/dev/null; then
    cls='ASAN'
    sig=$(grep -oE 'AddressSanitizer:[^"]*' "$log" | head -1 | tr ',' ';')
  elif grep -qE 'runtime error|UndefinedBehaviorSanitizer' "$log" 2>/dev/null; then
    cls='UBSAN'
    sig=$(grep -oE 'runtime error:[^"]*' "$log" | head -1 | tr ',' ';')
  elif grep -qE 'Assertion .* failed|assert.*failed' "$log" 2>/dev/null; then
    cls='ABORT'
    sig=$(grep -oE "Assertion '[^']*' failed" "$log" | head -1 | tr ',' ';')
  elif [ "$rc" = 134 ]; then
    cls='ABORT'
  elif [ "$rc" = 139 ]; then
    cls='SEGV'
  elif [ "$rc" = 124 ]; then
    cls='TIMEOUT'
  elif [ "$rc" = 0 ]; then
    cls='CLEAN'
  else
    cls='FAIL'
    sig=$(tail -1 "$log" | tr ',' ';' | head -c 200)
  fi

  printf '%s,%s,%s,"%s"\n' "$short" "$rc" "$cls" "$sig" >> "$SUMMARY"
  echo "[$count] $short -> rc=$rc cls=$cls"
done

echo
echo "=== summary by classification (label=$LABEL) ==="
awk -F, 'NR>1 {print $3}' "$SUMMARY" | sort | uniq -c | sort -rn
