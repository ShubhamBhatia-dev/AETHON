#!/usr/bin/env bash
# One command to test everything.
#
#   tests/run_all.sh            offline tests; live tests too if sudo is available
#   tests/run_all.sh --offline  only the offline tests (no root, no network)
#   tests/run_all.sh --internal same as --offline (internal unit/regression tests)
#   tests/run_all.sh --no-build skip the cmake build step and run existing binaries
#   tests/run_all.sh --fast     skip build + only internal tests (--internal --no-build)
#   tests/run_all.sh --full     live suite runs torture.sh --long as well
#
# Offline tests need nothing. Live tests need root (XDP/AF_XDP), nginx and node,
# and are skipped automatically if those are missing.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
cd "$ROOT"

OFFLINE_ONLY=0
NO_BUILD=0
TORTURE_ARGS="--quick"
for a in "$@"; do
  case "$a" in
    --offline|--internal) OFFLINE_ONLY=1 ;;
    --no-build|--test-only) NO_BUILD=1 ;;
    --fast) OFFLINE_ONLY=1; NO_BUILD=1 ;;
    --full) TORTURE_ARGS="--long" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
red()  { printf '\033[91m%s\033[0m\n' "$*"; }
grn()  { printf '\033[92m%s\033[0m\n' "$*"; }
FAILED=0
run() {  # run <label> <cmd...>
  bold "── $1"
  if "${@:2}"; then grn "   ok"; else red "   FAILED: $1"; FAILED=1; fi
}

if [[ $NO_BUILD -eq 0 ]]; then
  bold "═══ Build ═══"
  if ! cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1 || \
     ! cmake --build build -j >/tmp/aethon_build.log 2>&1; then
    red "build failed:"; tail -20 /tmp/aethon_build.log; exit 1
  fi
  grn "build ok"
else
  bold "═══ Skipping Build (--no-build) ═══"
fi

bold "═══ Offline tests (no root) ═══"
run "TCP reassembly regression" ./build/src/test_tcp_reassembly
run "TCP randomized fuzz"        ./build/src/test_tcp_fuzz
run "JA3 rate limiter"           ./build/src/test_ja3_ratelimit
run "DPI rule set (compile+coverage; ~45s first run, cached after)" ./build/src/test_dpi_rules

if [[ $OFFLINE_ONLY -eq 1 ]]; then
  echo; [[ $FAILED -eq 0 ]] && grn "ALL OFFLINE TESTS PASSED" || red "SOME OFFLINE TESTS FAILED"
  exit $FAILED
fi

# ----- live tests (root + nginx + node) -----
echo
bold "═══ Live end-to-end tests (need root, nginx, node) ═══"
MISSING=""
command -v nginx >/dev/null || MISSING="$MISSING nginx"
command -v node  >/dev/null || MISSING="$MISSING node"
if [[ -n "$MISSING" ]]; then
  red "   skipped: missing$MISSING (install them to run live tests)"
  echo; [[ $FAILED -eq 0 ]] && grn "OFFLINE PASSED; live skipped" || red "SOME TESTS FAILED"
  exit $FAILED
fi
if ! sudo -n true 2>/dev/null; then
  red "   skipped: live tests need sudo. Re-run as:  sudo -v && tests/run_all.sh"
  echo; [[ $FAILED -eq 0 ]] && grn "OFFLINE PASSED; live skipped (no sudo)" || red "SOME TESTS FAILED"
  exit $FAILED
fi

# Clean up any rogue python test backends
pkill -f multi_backend_server.py 2>/dev/null || true
pkill -f flask_backend.py 2>/dev/null || true

# Bring up stack + Aethon, run suites, tear down.
AETHON_PID=""
ALREADY_RUNNING=0
if pgrep -f afxdp_control >/dev/null; then
  ALREADY_RUNNING=1
  AETHON_PID=$(pgrep -f afxdp_control | head -n1)
fi

cleanup() {
  if [[ $ALREADY_RUNNING -eq 0 && -n "$AETHON_PID" ]]; then
    sudo kill "$AETHON_PID" 2>/dev/null || true
  fi
  "$DIR/web_app_test/stop.sh" --net >/dev/null 2>&1 || true
}
trap cleanup EXIT

run "web stack up (nginx + node + veth)" "$DIR/web_app_test/start.sh"

if [[ $ALREADY_RUNNING -eq 1 ]]; then
  bold "── Aethon Gateway on veth0"
  grn "   already running (pid $AETHON_PID)"
else
  bold "── starting Aethon on veth0"
  sudo ./build/src/afxdp_control veth0 >/tmp/aethon_run.log 2>&1 &
  AETHON_PID=$!
  sleep 3
  if ! sudo kill -0 "$AETHON_PID" 2>/dev/null; then
    red "   Aethon failed to start:"; tail -20 /tmp/aethon_run.log; FAILED=1
  else
    grn "   Aethon running (pid $AETHON_PID)"
  fi
fi

if sudo kill -0 "$AETHON_PID" 2>/dev/null; then
  run "end-to-end (clean fast-path)"               "$DIR/web_app_test/test.sh"
  run "end-to-end (50ms delay, 2% loss network chaos)" "$DIR/web_app_test/test.sh" --netem
  run "torture suite (chaos, jitter, edge cases)"  "$DIR/web_app_test/torture.sh" $TORTURE_ARGS
  run "wire-speed throughput benchmark (multi-stream line rate)" "$DIR/speed_test.sh" --streams 8 --size 5 --duration 3
  run "performance comparison: raw nginx vs aethon (with & without tls)" sudo "$DIR/compare_nginx_aethon.sh" --quick
  run "zero-trust security interception & FluxIO audit WAL" sudo "$DIR/test_live.sh" --quick
  run "functional features (routing, SNI, blocklist, integrity)" sudo "$DIR/test_features.sh"
  bold "── Aethon event counters (why connections were reset/dropped)"
  grep -h "\[Events\]" /tmp/aethon_run.log 2>/dev/null | tail -3 || echo "   (none)"
fi

echo
[[ $FAILED -eq 0 ]] && grn "═══ ALL TESTS PASSED ═══" || red "═══ SOME TESTS FAILED ═══"
exit $FAILED
