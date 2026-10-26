#!/usr/bin/env bash
#
# mayhem/build.sh — builds the NetX Duo crypto library (crypto_libraries/, standalone: no ThreadX) twice:
#   1) sanitized (ASan+UBSan, halting) + DWARF 3, linked into five libFuzzer harnesses (+ -standalone repro binaries)
#   2) with the project's normal flags, linked into upstream's own crypto regression tests and a KAT probe
# Idempotent and air-gapped. Everything generated lives under build/ (gitignored upstream).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
[ -w "$OUT" ] || OUT="$SRC/build/out"
mkdir -p "$OUT"

# The upstream linux port header defines ULONG as 64-bit, which breaks the big-number code on LP64;
# mayhem/port/nx_crypto_port.h (found first) keeps ULONG/LONG 32-bit.
DEFS="-DNX_CRYPTO_STANDALONE_ENABLE -DNX_CRYPTO_ENABLE_CURVE25519_448"
INC="-I$SRC/mayhem/port -I$SRC/crypto_libraries/inc"

# Everything except the ThreadX/TLS glue (needs tx_api.h) and the FIPS module entry points.
mapfile -t LIBSRC < <(ls "$SRC"/crypto_libraries/src/*.c | grep -v -e nx_crypto_generic_ciphersuites -e module_start)

# Sanitizer relaxations (recorded in the PR): upstream hmac calls through a differently-typed function
# pointer (-fsanitize=function) and the AES / huge-number code shifts an int into the sign bit
# (-fsanitize=shift-base). ASan and every other UBSan check stay on and halting.
san_extra() {
  case "$(basename "$1")" in
    nx_crypto_aes.c|nx_crypto_huge_number.c) echo "-fno-sanitize=function -fno-sanitize=shift-base" ;;
    *) echo "-fno-sanitize=function" ;;
  esac
}

# ---- 1) sanitized library + fuzzers ---------------------------------------------------------------
SAN="$SRC/build/mayhem-san"
rm -rf "$SAN"; mkdir -p "$SAN"
compile_san() {
  local f="$1" extra
  extra="$(san_extra "$f")"
  # shellcheck disable=SC2086
  $CC -c $SANITIZER_FLAGS $extra $DEBUG_FLAGS -fsanitize=fuzzer-no-link $DEFS $INC -std=c99 -w "$f" \
      -o "$SAN/$(basename "$f" .c).o"
}
export -f compile_san san_extra
export DEFS INC SAN
printf '%s\n' "${LIBSRC[@]}" | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_san {}'
ar rcs "$SAN/libnxcrypto.a" "$SAN"/*.o

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SAN/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SAN/standalone_main.o"

for t in fuzz_hash_mac fuzz_hkdf fuzz_cipher fuzz_ecc fuzz_rsa; do
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -fno-sanitize=function $DEBUG_FLAGS $LIB_FUZZING_ENGINE $DEFS $INC -w \
      "$SRC/mayhem/$t.c" "$SAN/libnxcrypto.a" "$SAN/lsan_off.o" -o "$OUT/$t"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -fno-sanitize=function $DEBUG_FLAGS $DEFS $INC -w \
      "$SRC/mayhem/$t.c" "$SAN/standalone_main.o" "$SAN/libnxcrypto.a" "$SAN/lsan_off.o" -lstdc++ -o "$OUT/$t-standalone"
done

# ---- 2) oracle: project's normal flags, no sanitizers ---------------------------------------------
ORC="$SRC/build/oracle"
rm -rf "$ORC"; mkdir -p "$ORC/lib"
TINC="$INC -I$SRC/test/regression/nx_secure_test"
TDEFS="$DEFS -DBATCH_TEST -DCTEST"
compile_orc() {
  # shellcheck disable=SC2086
  $CC -c -O1 $COVERAGE_FLAGS -std=gnu99 -w $DEFS $INC "$1" -o "$ORC/lib/$(basename "$1" .c).o"
}
export -f compile_orc
export ORC CC COVERAGE_FLAGS
printf '%s\n' "${LIBSRC[@]}" | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_orc {}'
ar rcs "$ORC/libnxcrypto.a" "$ORC"/lib/*.o

$CC -c -O1 $COVERAGE_FLAGS -std=gnu99 -w $TDEFS $TINC "$SRC/test/regression/crypto_test/cryptotestcontrol.c" -o "$ORC/ctl.o"

# Upstream's crypto regression list (test/cmake/crypto/regression/CMakeLists.txt) minus
# nx_secure_rsa_error_checking_test, which does not compile standalone (uses TX_SUCCESS).
TESTS=$(grep -o 'nx_secure_[a-z0-9_]*_test\.c' "$SRC/test/cmake/crypto/regression/CMakeLists.txt" \
        | grep -v -x 'nx_secure_rsa_error_checking_test.c' | sort -u)
mkdir -p "$ORC/tests"
for f in $TESTS; do
  echo "$f"
done | xargs -P "$MAYHEM_JOBS" -I{} bash -c '
  f={}; t=${f%.c}
  $CC -O1 $COVERAGE_FLAGS -std=gnu99 -w '"$TDEFS $TINC"' "'"$SRC"'/test/regression/nx_secure_test/$f" \
      "$ORC/ctl.o" "$ORC/libnxcrypto.a" -o "$ORC/tests/$t"'
printf '%s\n' $TESTS | sed 's/\.c$//' > "$ORC/tests.list"

$CC -O1 $COVERAGE_FLAGS -std=gnu99 -w $DEFS $INC "$SRC/mayhem/kat.c" "$ORC/libnxcrypto.a" -o "$ORC/kat"

# test.sh relies on dynamic linking so that the sabotage shim can neuter these binaries.
for b in "$ORC/kat" "$ORC/tests/nx_secure_md5_test"; do
  file "$b" | grep -q 'dynamically linked'
done
echo "build ok"
