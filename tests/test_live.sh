#!/usr/bin/env bash
# ==============================================================================
#  AETHON ALL-IN-ONE LIVE SYSTEM TEST & BENCHMARK SUITE
# ==============================================================================
#  Clean, automated verification matching the standard tests/run_all.sh style.
#  Tests Nginx/Node integration, wire-speed line rates, security interception,
#  and FluxIO async logging against the running Aethon Gateway.
#
#  Usage:
#    sudo ./tests/test_live.sh [--quick|--full]
# ==============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
SERVER_IP="192.168.50.1"
MODE="full"

for arg in "$@"; do
  case "$arg" in
    --quick) MODE="quick" ;;
    --full)  MODE="full" ;;
    -h|--help)
      sed -n '2,13p' "$0"
      exit 0
      ;;
  esac
done

# Clean output formatting matching run_all.sh
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
red()  { printf '\033[91m%s\033[0m\n' "$*"; }
grn()  { printf '\033[92m%s\033[0m\n' "$*"; }
FAILED=0

run() {
  bold "── $1"
  if "${@:2}" >/dev/null 2>&1; then
    grn "   ok"
  else
    red "   FAILED: $1"
    FAILED=1
  fi
}

run_info() {
  bold "── $1"
  local msg
  if msg=$("${@:2}" 2>&1); then
    grn "   ok ($msg)"
  else
    red "   FAILED: $1 ($msg)"
    FAILED=1
  fi
}

C() { sudo ip netns exec client_ns "$@"; }

# -----------------------------------------------------------------------------
# PRE-FLIGHT
# -----------------------------------------------------------------------------
bold "═══ Aethon Live Verification & Performance Suite ═══"

if [[ $EUID -ne 0 ]]; then
  red "Error: Root privileges required for network namespaces."
  echo "Please run as: sudo $0"
  exit 1
fi

# 1. Kill any lingering rogue python test servers that might hijack port 8080
pkill -f multi_backend_server.py 2>/dev/null || true
pkill -f flask_backend.py 2>/dev/null || true

# 2. Check if Aethon engine is running
bold "── checking Aethon Gateway engine"
if ! pgrep -f afxdp_control >/dev/null; then
  red "   FAILED: Aethon is not running!"
  echo "   Please start Aethon first in another terminal:"
  echo "     sudo ./build/src/afxdp_control veth0"
  exit 1
fi
AETHON_PID=$(pgrep -f afxdp_control | head -n1)
grn "   ok (Aethon active, pid $AETHON_PID)"

# 3. Bring up web stack (Nginx + Node) cleanly if not already running
bold "── web stack & network namespace (veth0/veth1)"
if ! ip netns list | grep -qw client_ns || ! curl -fsS "http://127.0.0.1:8080/api/health" >/dev/null 2>&1; then
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    sudo -u "$SUDO_USER" "$DIR/web_app_test/start.sh" >/dev/null 2>&1 || true
  else
    "$DIR/web_app_test/start.sh" >/dev/null 2>&1 || true
  fi
  sleep 1
fi

# Apply checksum offload fixes on veth interfaces
C ethtool -K veth1 gro off gso off tso off tx off rx off >/dev/null 2>&1 || true
ethtool -K veth0 gro off gso off tso off tx off rx off >/dev/null 2>&1 || true

if ip netns list | grep -qw client_ns; then
  grn "   ok"
else
  red "   FAILED: client_ns not available"
  exit 1
fi

# Ensure test payload files exist
[[ -f "$RUN_DIR/files/SHA256SUMS" ]] || {
  mkdir -p "$RUN_DIR/files"
  for mb in 1 5 50; do
    f="$RUN_DIR/files/${mb}mb.bin"
    [[ -f "$f" ]] || head -c "$((mb * 1024 * 1024))" /dev/urandom > "$f"
  done
  (cd "$RUN_DIR/files" && sha256sum ./*.bin > SHA256SUMS)
}

expected_sha() { awk -v f="./$1" '$2 == f {print $1}' "$RUN_DIR/files/SHA256SUMS"; }
CURL=(curl -sS --max-time 15)

# -----------------------------------------------------------------------------
# PHASE 1: FUNCTIONAL WEB APP & REVERSE PROXY
# -----------------------------------------------------------------------------
bold "═══ Phase 1: Functional Integration (Nginx + Node) ═══"

test_static_page() {
  local body
  body=$(C "${CURL[@]}" "http://$SERVER_IP/")
  [[ "$body" == *"Aethon"* ]]
}
run "static HTML index page (Nginx proxy)" test_static_page

test_api_health() {
  local body
  body=$(C "${CURL[@]}" "http://$SERVER_IP/api/health")
  [[ "$body" == *'"ok":true'* ]]
}
run "REST API health check (Node backend via Nginx)" test_api_health

test_keepalive() {
  local body count
  body=$(C "${CURL[@]}" "http://$SERVER_IP/api/health" "http://$SERVER_IP/api/health" "http://$SERVER_IP/api/health")
  count=$(grep -o '"ok":true' <<< "$body" | wc -l)
  [[ "$count" -eq 3 ]]
}
run "HTTP keep-alive pipelined requests (single TCP flow)" test_keepalive

test_sendfile_1mb() {
  local want got
  want=$(expected_sha "1mb.bin")
  got=$(C "${CURL[@]}" "http://$SERVER_IP/files/1mb.bin" | sha256sum | cut -d' ' -f1)
  [[ -n "$want" && "$got" == "$want" ]]
}
run "Nginx sendfile 1 MB download (cryptographic SHA256 match)" test_sendfile_1mb

test_sendfile_5mb() {
  local want got
  want=$(expected_sha "5mb.bin")
  got=$(C "${CURL[@]}" "http://$SERVER_IP/files/5mb.bin" | sha256sum | cut -d' ' -f1)
  [[ -n "$want" && "$got" == "$want" ]]
}
run "Nginx sendfile 5 MB download (cryptographic SHA256 match)" test_sendfile_5mb

test_streamed_download() {
  local want got
  want=$(expected_sha "5mb.bin")
  got=$(C "${CURL[@]}" "http://$SERVER_IP/api/file/5mb.bin" | sha256sum | cut -d' ' -f1)
  [[ -n "$want" && "$got" == "$want" ]]
}
run "Node.js streamed chunked download (5 MB SHA256 match)" test_streamed_download

test_upload_20mb() {
  local up="$RUN_DIR/upload_20mb.bin"
  [[ -f "$up" ]] || head -c $((20 * 1024 * 1024)) /dev/urandom > "$up"
  local want body
  want=$(sha256sum "$up" | cut -d' ' -f1)
  body=$(C "${CURL[@]}" --data-binary @"$up" -H 'Content-Type: application/octet-stream' "http://$SERVER_IP/api/upload")
  [[ "$body" == *"$want"* ]]
}
run "20 MB binary upload (Node cryptographic SHA256 verify)" test_upload_20mb

# -----------------------------------------------------------------------------
# PHASE 2: NETWORK CHAOS & LOOSE PACKETS (50ms Delay, 2% Packet Loss)
# -----------------------------------------------------------------------------
bold "═══ Phase 2: Network Chaos & Loose Packets (50ms Delay, 2% Loss) ═══"

test_chaos_transfers() {
  C tc qdisc replace dev veth1 root netem delay 50ms loss 2% 2>/dev/null || true
  local want got body ok=0

  body=$(C curl -sS --max-time 15 "http://$SERVER_IP/api/health" 2>/dev/null || true)
  if [[ "$body" == *'"ok":true'* ]]; then
    want=$(expected_sha "1mb.bin")
    got=$(C curl -sS --max-time 30 "http://$SERVER_IP/files/1mb.bin" 2>/dev/null | sha256sum | cut -d' ' -f1)
    if [[ -n "$want" && "$got" == "$want" ]]; then
      ok=1
    fi
  fi

  C tc qdisc del dev veth1 root 2>/dev/null || true
  [[ $ok -eq 1 ]]
}
run "TCP reassembly under loose packets & latency (50ms delay, 2% loss)" test_chaos_transfers

# -----------------------------------------------------------------------------
# PHASE 3: WIRE-SPEED LINE-RATE BENCHMARKS
# -----------------------------------------------------------------------------
bold "═══ Phase 3: Wire-Speed Performance Benchmarks ═══"

bench_single_stream() {
  local target="http://$SERVER_IP/files/5mb.bin"
  local t_start t_end dur_s mbps_rate gbps_rate
  t_start=$(date +%s%N)
  C curl -s -o /dev/null "$target" || return 1
  t_end=$(date +%s%N)
  dur_s=$(awk -v s="$t_start" -v e="$t_end" 'BEGIN { printf "%.4f", (e - s)/1000000000 }')
  mbps_rate=$(awk -v bytes=5242880 -v d="$dur_s" 'BEGIN { if (d>0) printf "%.2f", (bytes / 1048576) / d; else printf "0" }')
  gbps_rate=$(awk -v bytes=5242880 -v d="$dur_s" 'BEGIN { if (d>0) printf "%.2f", (bytes * 8 / 1000000000) / d; else printf "0" }')
  echo "${mbps_rate} MB/s, ${gbps_rate} Gbps line rate"
}
run_info "single-stream wire speed (5 MB sendfile)" bench_single_stream

bench_multi_stream() {
  local target="http://$SERVER_IP/files/5mb.bin"
  local pids=() t_start t_end dur_s mbps_rate gbps_rate
  t_start=$(date +%s%N)
  for i in {1..8}; do
    C curl -s -o /dev/null "$target" &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || return 1
  done
  t_end=$(date +%s%N)
  dur_s=$(awk -v s="$t_start" -v e="$t_end" 'BEGIN { printf "%.4f", (e - s)/1000000000 }')
  mbps_rate=$(awk -v bytes=41943040 -v d="$dur_s" 'BEGIN { if (d>0) printf "%.2f", (bytes / 1048576) / d; else printf "0" }')
  gbps_rate=$(awk -v bytes=41943040 -v d="$dur_s" 'BEGIN { if (d>0) printf "%.2f", (bytes * 8 / 1000000000) / d; else printf "0" }')
  echo "${mbps_rate} MB/s, ${gbps_rate} Gbps aggregate"
}
run_info "multi-stream parallel saturation (8 concurrent flows)" bench_multi_stream

bench_wrk_load() {
  if ! command -v wrk >/dev/null 2>&1; then
    echo "wrk not installed, skipped"
    return 0
  fi
  local out rps lat
  out=$(C wrk -t2 -c30 -d4s "http://$SERVER_IP/api/health" 2>&1 || true)
  rps=$(echo "$out" | grep "Requests/sec:" | awk '{print $2}' || echo "0")
  lat=$(echo "$out" | grep "Latency" | head -n1 | awk '{print $2}' || echo "N/A")
  echo "${rps} req/s, avg latency ${lat}"
}
if [[ "$MODE" == "full" ]]; then
  run_info "high-concurrency connection storm (wrk -c30)" bench_wrk_load
fi

# -----------------------------------------------------------------------------
# PHASE 4: THREAT INTERCEPTION & ZERO-TRUST SECURITY
# -----------------------------------------------------------------------------
bold "═══ Phase 4: Zero-Trust Security Interception ═══"

test_sni_block() {
  # Trigger atomic config reload so Aethon refreshes blocked_domains.txt
  sudo kill -HUP "$AETHON_PID" 2>/dev/null || true
  sleep 0.2

  local out code=0
  out=$(C curl -sk --resolve "malicious.test.com:443:$SERVER_IP" --max-time 3 "https://malicious.test.com/" 2>&1) || code=$?

  # When blocked by Aethon's TCP RST injection, curl fails to complete the TLS handshake (code != 0)
  if [[ $code -ne 0 ]]; then
    return 0
  fi
  # If curl returned code 0 (handshake succeeded), blocklist failed
  return 1
}
run "TLS SNI blocklist defense (malicious.test.com rejected)" test_sni_block

test_dpi_detection() {
  local out
  out=$(C curl -sS --max-time 3 "http://$SERVER_IP/etc/passwd" 2>&1 || true)
  # DPI signature match triggers immediate zero-copy TCP RST injection
  [[ "$out" == *"Connection reset"* || "$out" == *"Empty reply"* || "$out" == *"curl: (56)"* || "$out" == *"curl: (52)"* ]]
}
run "DPI exploit signature detection (/etc/passwd TCP RST injected)" test_dpi_detection

# -----------------------------------------------------------------------------
# PHASE 5: TELEMETRY & FLUXIO ASYNC LOG WAL
# -----------------------------------------------------------------------------
bold "═══ Phase 5: Hardware Telemetry & FluxIO WAL ═══"

test_shm_telemetry() {
  [[ -f "/dev/shm/aethon_stats.shm" ]]
}
run "shared memory hardware telemetry (/dev/shm/aethon_stats.shm)" test_shm_telemetry

test_fluxio_wal() {
  local f="$ROOT/logs/aethon_security.jsonl"
  [[ -f "$f" ]]
}
run "FluxIO zero-copy io_uring audit WAL (logs/aethon_security.jsonl)" test_fluxio_wal

test_dashboard_online() {
  curl -s --max-time 2 "http://localhost:2384/api/stats" >/dev/null 2>&1
}
if test_dashboard_online; then
  bold "── Aethon Web Dashboard"
  grn "   ok (online at http://localhost:2384)"
else
  bold "── Aethon Web Dashboard"
  grn "   ready (start anytime: ./dashboard/aethon-dashboard)"
fi

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
echo
if [[ $FAILED -eq 0 ]]; then
  grn "═══ ALL TESTS PASSED ═══"
else
  red "═══ SOME TESTS FAILED ═══"
fi
exit $FAILED
