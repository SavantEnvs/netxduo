#!/usr/bin/env bash
#
# mayhem/test.sh — RUN upstream's NetX Duo crypto regression tests plus known-answer probes (all built by
# mayhem/build.sh). exit 0 = pass.
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


ORC="$SRC/build/oracle"
[ -d "$ORC/tests" ] && [ -x "$ORC/kat" ] || { echo "oracle binaries missing: run mayhem/build.sh" >&2; emit_ctrf "netxduo-crypto" 0 1 0; exit 1; }

passed=0; failed=0

# 1) Upstream's crypto regression tests (test/regression/nx_secure_test): each prints "<name>....SUCCESS!"
#    or "FAILED!"; the verdict is read here in bash, from the program's own output.
while read -r t; do
  out=$(cd "$SRC/test/cmake/crypto" && timeout 600 "$ORC/tests/$t" 2>&1)
  if printf '%s\n' "$out" | grep -q 'SUCCESS!' && ! printf '%s\n' "$out" | grep -qi 'FAIL'; then
    passed=$((passed+1))
  else
    failed=$((failed+1)); echo "FAIL: $t :: $(printf '%s' "$out" | tail -c 200)"
  fi
done < "$ORC/tests.list"

# 2) KAT probe: fixed inputs -> exact outputs from FIPS 180 / FIPS 197 / RFC 4231 / RFC 5869.
kat_out=$("$ORC/kat" 2>&1)
expect() {
  if printf '%s\n' "$kat_out" | grep -qx -- "$1"; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL KAT: expected '$1'"; fi
}
expect 'md5_abc=900150983cd24fb0d6963f7d28e17f72'
expect 'sha256_abc=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
expect 'hmac_sha256_jefe=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
expect 'aes128_fips197=69c4e0d86a7b0430d8cdb78070b4c55a'
expect 'hkdf_prk=077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'
expect 'hkdf_okm=3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'

emit_ctrf "netxduo-crypto" "$passed" "$failed" 0
