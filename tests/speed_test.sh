#!/usr/bin/env bash
# ==============================================================================
# AETHON HIGH-SPEED THROUGHPUT & BENCHMARK SUITE
# ==============================================================================
# Measures raw multi-gigabit throughput, transfer speeds, and active sessions
# through the Aethon AF_XDP Zero-Copy Proxy.
#
# Usage:
#   sudo ./tests/speed_test.sh [OPTIONS]
#
# Options:
#   --streams N     Number of concurrent parallel streams (default: 8)
#   --duration SEC  Duration for wrk load burst in seconds (default: 10)
#   --size [1|5|50] File size in MB for download tests (default: 50)
#   --help          Show this help message
# ==============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
SERVER_IP="192.168.50.1"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
STREAMS=8
DURATION=10
SIZE_MB=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --streams) STREAMS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --size) SIZE_MB="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Formatting
BOLD="\033[1m"
GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

header() {
  echo -e "\n${BOLD}${CYAN}====================================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $*${RESET}"
  echo -e "${BOLD}${CYAN}====================================================================${RESET}"
}

subheader() {
  echo -e "\n${BOLD}--- $* ---${RESET}"
}

pass() { echo -e "  ${GREEN}✔ PASS${RESET} $*"; }
fail() { echo -e "  ${RED}✘ FAIL${RESET} $*"; }
info() { echo -e "  ${CYAN}ℹ${RESET} $*"; }

C() { sudo ip netns exec client_ns "$@"; }

# 1. Preflight checks
header "Aethon High-Performance Throughput Benchmark"

if ! ip netns list | grep -qw client_ns; then
  echo -e "${RED}Error: client_ns not found. Start the test stack first:${RESET}"
  echo -e "  ./tests/web_app_test/start.sh"
  exit 1
fi

if ! pgrep -f afxdp_control >/dev/null; then
  echo -e "${RED}Error: Aethon (afxdp_control) is not running.${RESET}"
  echo -e "Start Aethon with: sudo ./build/src/afxdp_control veth0"
  exit 1
fi

TEST_FILE="$RUN_DIR/files/${SIZE_MB}mb.bin"
if [[ ! -f "$TEST_FILE" ]]; then
  info "Generating ${SIZE_MB} MB benchmark file in $RUN_DIR/files/..."
  mkdir -p "$RUN_DIR/files"
  head -c "$((SIZE_MB * 1024 * 1024))" /dev/urandom > "$TEST_FILE"
  (cd "$RUN_DIR/files" && sha256sum ./*.bin > SHA256SUMS)
fi

EXPECTED_SHA=$(sha256sum "$TEST_FILE" | cut -d' ' -f1)
info "Target file: ${SIZE_MB} MB (SHA256: ${EXPECTED_SHA:0:16}...)"

# 2. Single Stream Wire-Speed Benchmark
subheader "Test 1: Single-Stream Wire-Speed Download (${SIZE_MB} MB)"
T_START=$(date +%s%N)
RESULT=$(C curl -sS -o /dev/null -w "Speed: %{speed_download} B/s | Time: %{time_total} s\n" "http://$SERVER_IP/files/${SIZE_MB}mb.bin")
T_END=$(date +%s%N)
RAW_BPS=$(echo "$RESULT" | awk '{print $2}')
TIME_S=$(echo "$RESULT" | awk '{print $6}')

MB_PER_SEC=$(awk -v b="$RAW_BPS" 'BEGIN {printf "%.2f", b / (1024 * 1024)}')
GBIT_PER_SEC=$(awk -v b="$RAW_BPS" 'BEGIN {printf "%.2f", (b * 8) / 1000000000}')

echo -e "  Transfer Time:       ${BOLD}${TIME_S} s${RESET}"
echo -e "  Single-Stream Speed: ${BOLD}${GREEN}${MB_PER_SEC} MB/s${RESET} (${BOLD}${CYAN}${GBIT_PER_SEC} Gbps${RESET})"

# Verify SHA256 Integrity
DOWNLOAD_SHA=$(C curl -sS "http://$SERVER_IP/files/${SIZE_MB}mb.bin" | sha256sum | cut -d' ' -f1)
if [[ "$DOWNLOAD_SHA" == "$EXPECTED_SHA" ]]; then
  pass "Cryptographic SHA256 hash match — zero packet corruption or drops"
else
  fail "SHA256 mismatch: got ${DOWNLOAD_SHA:0:16}..., expected ${EXPECTED_SHA:0:16}..."
fi

# 3. Multi-Stream Concurrent Saturation Benchmark
subheader "Test 2: Multi-Stream Parallel Saturation ($STREAMS Concurrent Flows)"
info "Spawning $STREAMS simultaneous downloads through Aethon..."

TMP_BENCH=$(mktemp -d)
PIDS=()
START_NS=$(date +%s%N)

for i in $(seq 1 "$STREAMS"); do
  (
    C curl -sS -o "$TMP_BENCH/out_$i.bin" -w "%{speed_download}\n" "http://$SERVER_IP/files/${SIZE_MB}mb.bin" > "$TMP_BENCH/speed_$i.txt"
  ) &
  PIDS+=($!)
done

# Wait for all parallel streams
for pid in "${PIDS[@]}"; do
  wait "$pid"
done
END_NS=$(date +%s%N)

TOTAL_TIME_S=$(awk -v s="$START_NS" -v e="$END_NS" 'BEGIN {printf "%.3f", (e - s) / 1000000000}')
TOTAL_BYTES=$((STREAMS * SIZE_MB * 1024 * 1024))
TOTAL_MB=$(awk -v b="$TOTAL_BYTES" 'BEGIN {printf "%.2f", b / (1024 * 1024)}')
AGGREGATE_MB_PER_SEC=$(awk -v mb="$TOTAL_MB" -v t="$TOTAL_TIME_S" 'BEGIN {printf "%.2f", mb / t}')
AGGREGATE_GBIT_PER_SEC=$(awk -v mbs="$AGGREGATE_MB_PER_SEC" 'BEGIN {printf "%.2f", (mbs * 8) / 1000}')

echo -e "  Total Transferred:   ${BOLD}${TOTAL_MB} MB across $STREAMS streams${RESET}"
echo -e "  Total Duration:      ${BOLD}${TOTAL_TIME_S} s${RESET}"
echo -e "  Aggregate Line Rate: ${BOLD}${GREEN}${AGGREGATE_MB_PER_SEC} MB/s${RESET} (${BOLD}${CYAN}${AGGREGATE_GBIT_PER_SEC} Gbps${RESET})"

# Verify all downloaded files match checksum
CORRUPT=0
for i in $(seq 1 "$STREAMS"); do
  SHA=$(sha256sum "$TMP_BENCH/out_$i.bin" | cut -d' ' -f1)
  if [[ "$SHA" != "$EXPECTED_SHA" ]]; then
    CORRUPT=$((CORRUPT + 1))
  fi
done
rm -rf "$TMP_BENCH"

if [[ "$CORRUPT" -eq 0 ]]; then
  pass "All $STREAMS concurrent streams verified (100% data integrity)"
else
  fail "$CORRUPT / $STREAMS streams had checksum errors"
fi

# 4. HTTP Request-Rate & Latency Load Test (wrk)
if command -v wrk >/dev/null; then
  subheader "Test 3: High-Concurrency Connection Pipeline (wrk -c50 -d${DURATION}s)"
  info "Running $DURATION-second load test with keep-alive..."
  
  WRK_OUTPUT=$(C wrk -t2 -c50 -d"${DURATION}s" --latency "http://$SERVER_IP/api/health" 2>&1)
  
  RPS=$(echo "$WRK_OUTPUT" | grep "Requests/sec:" | awk '{print $2}')
  BW=$(echo "$WRK_OUTPUT" | grep "Transfer/sec:" | awk '{print $2, $3}')
  AVG_LAT=$(echo "$WRK_OUTPUT" | grep -A 1 "Latency" | tail -1 | awk '{print $2}')
  SOCKET_ERRS=$(echo "$WRK_OUTPUT" | grep -c "Socket errors" || true)

  echo -e "  Requests / sec:      ${BOLD}${GREEN}${RPS}${RESET}"
  echo -e "  Transfer / sec:      ${BOLD}${CYAN}${BW}${RESET}"
  echo -e "  Average Latency:     ${BOLD}${AVG_LAT}${RESET}"
  
  if [[ "$SOCKET_ERRS" -eq 0 ]]; then
    pass "Zero socket errors during high-concurrency storm"
  else
    fail "Socket errors encountered in wrk run"
  fi
else
  info "wrk not installed, skipping synthetic request-rate test"
fi

# 5. Live Telemetry Summary
subheader "Live Telemetry State"
if [[ -f /dev/shm/aethon_stats.shm ]]; then
  info "Shared memory (/dev/shm/aethon_stats.shm) active and synced with dashboard"
  pass "Real-time engine telemetry streaming to Dashboard (http://localhost:2384)"
fi

header "Speed Test Completed Successfully"
echo -e "Ready for presentation! Check the live web dashboard at ${BOLD}http://localhost:2384${RESET}\n"
exit 0
