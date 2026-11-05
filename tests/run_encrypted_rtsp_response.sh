#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
"${CC:-cc}" -std=gnu11 -fsanitize=address,undefined -g -O1 \
  -fno-omit-frame-pointer -ffunction-sections -fdata-sections \
  -Wall -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration \
  -I"$repo/src" -I"$repo/enet/include" -I"$repo/nanors" \
  -I"$repo/nanors/deps" -I"$repo/nanors/deps/obl" \
  "$repo/tests/test_encrypted_rtsp_response.c" "$repo/src/RtspParser.c" \
  "$repo/src/PlatformCrypto.c" "$repo/src/Platform.c" "$repo/src/ByteBuffer.c" \
  -pthread -Wl,--gc-sections -lcrypto -o "$build/rtsp-driver"
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
export UBSAN_OPTIONS=halt_on_error=1
set +e
"$build/rtsp-driver" --check-fail >"$build/negative.log" 2>&1
status=$?
set -e
test "$status" -eq 2
grep -q 'CHECK failed: false' "$build/negative.log"
"$build/rtsp-driver"
