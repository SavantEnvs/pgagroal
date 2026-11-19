#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's MCTF runner (test/runner.c), built by build.sh. Only the tests that need no running
# PostgreSQL / pgagroal are run. The runner's `-m` and `-t` filters are both substring matches
# (test/libpgagroaltest/mctf.c, matches_filter), so every selection below is chosen to match only
# offline tests, and no test is selected twice:
#  * modules (-m): AES, deque, JSON, utils, HBA matching, message framing (`message` also selects
#    `message_complete` and `message_split_callback`), secure compare, reserved names, password
#    length, configuration parsing, TLS, pool backoff (pure retry-delay math and its config
#    validation; `pool_backoff` does not match `pool_saturation`);
#  * tests (-t): the in-memory ART (`-t test_art_`; `-m art` would also pick `startup_validation`),
#    and the 7 startup-validation tests that only read and validate test/conf/07..13 or return
#    before any query (startup_validation off / no health_check_user).
RUNNER="$SRC/build/mayhem-test/test/pgagroal_test"
SELECTIONS="-m:aes -m:deque -m:json -m:utils -m:hba -m:message -m:secure_compare -m:reserved_names \
-m:password_length -m:configuration -m:tls -m:pool_backoff -t:test_art_ \
-t:test_server_validation_duplicate_server_getaddrinfo -t:test_server_validation_duplicate_server_name \
-t:test_server_validation_multiple_primaries -t:test_server_validation_valid_config \
-t:test_startup_validation_off -t:test_startup_validation_try_no_user -t:test_startup_validation_on_no_user"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "mctf" 0 1 0
  exit 1
fi

# The runner reads <project>/pgagroal-testsuite/conf/pgagroal.conf (test/conf/01) at start-up.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pgagroal-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/pgagroal-testsuite/conf" "$WORK/pgagroal-testsuite/log"
cp "$SRC"/test/conf/01/* "$WORK/pgagroal-testsuite/conf/"
sed -i "s|^log_path = .*|log_path = $WORK/pgagroal-testsuite/log/pgagroal.log|" \
  "$WORK/pgagroal-testsuite/conf/pgagroal.conf"
# The startup-validation tests read <project>/test/conf/NN/pgagroal.conf.
ln -s "$SRC/test" "$WORK/test"
# Two ART tests read <project>/pgagroal-testsuite/resource/..., which upstream's test/check.sh copies.
cp -R "$SRC/test/resource" "$WORK/pgagroal-testsuite/"
export LLVM_PROFILE_FILE="$WORK/default-%p.profraw"   # upstream builds the runner with clang coverage

passed=0; failed=0
for sel in $SELECTIONS; do
  flag="${sel%%:*}"; m="${sel#*:}"
  out="$WORK/$m.out"
  (cd "$WORK" && "$RUNNER" "$flag" "$m" "$WORK" pgagroal pgagroal) >"$out" 2>&1
  rc=$?
  p=$(sed -n 's/.*Passed: *\([0-9][0-9]*\).*/\1/p' "$out" | tail -1)
  f=$(sed -n 's/.*Failed: *\([0-9][0-9]*\).*/\1/p' "$out" | tail -1)
  if [ -z "$p" ] || [ -z "$f" ]; then
    echo "$flag $m: no MCTF summary (rc=$rc)"; tail -20 "$out"
    failed=$((failed + 1)); continue
  fi
  if [ "$p" -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; }; then
    echo "$flag $m: rc=$rc passed=$p failed=$f — counted as a failure"
    f=$((f + 1))
  fi
  echo "$flag $m: passed=$p failed=$f"
  [ "$f" -gt 0 ] && grep -a -A2 -i "fail" "$out" | head -20
  passed=$((passed + p)); failed=$((failed + f))
done
emit_ctrf "mctf" "$passed" "$failed" 0
