#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Everything this script writes lives under build/ (upstream's .gitignore ignores it), so
# `git clean -ffdX` removes it and a re-run starts from the same place.
FUZZ_TARGETS="fuzz_json fuzz_utf8 fuzz_aes fuzz_message fuzz_management \
fuzz_authenticate fuzz_remote_auth fuzz_scram_client fuzz_config fuzz_hba fuzz_users"
AFL_TARGETS="fuzz_limit_file fuzz_prometheus_file"

ver() { sed -n "s/^set(VERSION_$1 \"\([0-9]*\)\")/\1/p" CMakeLists.txt; }
VMAJ=$(ver MAJOR); VMIN=$(ver MINOR); VPAT=$(ver PATCH)
# The definitions src/CMakeLists.txt adds on Linux (liburing >= 2.5 is installed, so io_uring is on).
PG_DEFS="-std=c17 -D__USE_ISOC11 -D_GNU_SOURCE -DHAVE_LINUX -D_POSIX_C_SOURCE=200809L -DHAVE_IO_URING \
-DHAVE_EXECINFO_H -DPGAGROAL_MAJOR_VERSION=$VMAJ -DPGAGROAL_MINOR_VERSION=$VMIN \
-DPGAGROAL_PATCH_VERSION=$VPAT -DPGAGROAL_VERSION=\"$VMAJ.$VMIN.$VPAT\" -Wno-deprecated-declarations"
PG_INC="-I$SRC/src/include -I$SRC/mayhem/harnesses"
PG_LIBS="-lssl -lcrypto -lz -lbz2 -lzstd -llz4 -luring -latomic -lpthread -lm"

# compile_lib <cc> <outdir> <flags...>: every src/libpgagroal/*.c into <outdir>/libpgagroal.a
compile_lib() {
  local cc="$1" out="$2"; shift 2
  mkdir -p "$out/obj"
  rm -f "$out/libpgagroal.a" "$out"/obj/*.o
  ls src/libpgagroal/*.c | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
    'f="$1"; shift; o="$0/obj/$(basename "$f" .c).o"; exec "$@" -c "$f" -o "$o"' \
    "$out" {} "$cc" "$@" $PG_DEFS $PG_INC
  ar rcs "$out/libpgagroal.a" "$out"/obj/*.o
}

# 1) The project's own test runner (test/runner.c + test/testcases), with upstream's NORMAL
#    CMake build (Release, its own flags) — mayhem/test.sh only runs it.
cmake -S . -B build/mayhem-test -DCMAKE_BUILD_TYPE=Release -DDOCS=OFF \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build build/mayhem-test -j"$MAYHEM_JOBS" --target pgagroal_test

# 2) libpgagroal with the sanitizers + SanCov, and the libFuzzer harnesses (+ standalone reproducers).
# UBSan's `alignment` check is relaxed (only that one): pgagroal declares its structs
# __attribute__((aligned(64))) and allocates them with malloc (16-byte aligned), so every access
# trips it. Upstream's own sanitizer build (test/CMakeLists.txt) passes -fno-sanitize=alignment too.
# Empty when SANITIZER_FLAGS is empty (the no-sanitizer build).
UBSAN_RELAX=""; case "$SANITIZER_FLAGS" in *undefined*) UBSAN_RELAX="-fno-sanitize=alignment";; esac
FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -O1"
compile_lib "$CC" build/mayhem-fuzz $FUZZ_CFLAGS -fsanitize=fuzzer-no-link
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/mayhem-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/mayhem-fuzz/standalone_main.o
for t in $FUZZ_TARGETS; do
  $CC $FUZZ_CFLAGS $PG_DEFS $PG_INC -fsanitize=fuzzer-no-link -c "mayhem/harnesses/$t.c" -o "build/mayhem-fuzz/$t.o"
  $CXX $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "build/mayhem-fuzz/$t.o" build/mayhem-fuzz/lsan_off.o \
       build/mayhem-fuzz/libpgagroal.a $PG_LIBS -o "/mayhem/$t"
  $CXX $FUZZ_CFLAGS build/mayhem-fuzz/standalone_main.o "build/mayhem-fuzz/$t.o" build/mayhem-fuzz/lsan_off.o \
       build/mayhem-fuzz/libpgagroal.a $PG_LIBS -o "/mayhem/$t-standalone"
done

# 3) The AFL file-input targets (the code under test exit()s by design): libpgagroal again with
#    afl-clang-fast, same sanitizers. An AFL binary is its own reproducer (no -standalone).
compile_lib afl-clang-fast build/mayhem-afl $FUZZ_CFLAGS
afl-clang-fast++ $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/mayhem-afl/lsan_off.o
for t in $AFL_TARGETS; do
  afl-clang-fast $FUZZ_CFLAGS $PG_DEFS $PG_INC -c "mayhem/harnesses/$t.c" -o "build/mayhem-afl/$t.o"
  afl-clang-fast++ $FUZZ_CFLAGS "build/mayhem-afl/$t.o" build/mayhem-afl/lsan_off.o \
       build/mayhem-afl/libpgagroal.a $PG_LIBS -o "/mayhem/$t"
done
