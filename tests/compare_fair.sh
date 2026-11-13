#!/usr/bin/env bash
# ==============================================================================
#  AETHON vs NGINX — HONEST, SAME-WIRE, SUSTAINED BENCHMARK
# ==============================================================================
#  Fairness: BOTH stacks are hit from the SAME client namespace, over the SAME
#  veth, at 1500 MTU with TSO/GSO/GRO disabled. Only the data path differs:
#       nginx (same wire):  client_ns -> veth -> KERNEL TCP -> nginx   (8081/8444)
#       Aethon:             client_ns -> veth -> AF_XDP -> Aethon -> nginx (80/443)
#  The old script compared Aethon-over-veth against nginx-over-LOOPBACK
#  (sendfile+TSO, 64 KB segments) — apples-to-oranges. This does not.
#
#  Duration: each throughput number is measured by looping downloads for a fixed
#  WINDOW (default 20s, --long 60s) and dividing total bytes by elapsed time, so
#  slow-start / scheduling noise averages out instead of dominating a 0.1s shot.
#
#  Needs the benchmark nginx listeners (8081/8444 on the veth IP). If missing:
#       tests/web_app_test/stop.sh ; tests/web_app_test/start.sh ; restart Aethon
#
#  Usage: sudo ./tests/compare_fair.sh [--window S] [--size MB] [--streams N]
#                                      [--quick] [--long]
# ==============================================================================
set -uo pipefail

RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
SERVER_IP="192.168.50.1"
TLS_HOST="test.local"
A_HTTP="http://$SERVER_IP"                 # Aethon-managed (AF_XDP)
N_HTTP="http://$SERVER_IP:8081"            # nginx over veth via kernel
N_HTTPS="https://$SERVER_IP:8444"
LO_HTTP="http://127.0.0.1:8080"            # loopback reference ceiling
LO_HTTPS="https://127.0.0.1:8443"

SIZE_MB=100; WINDOW=20; STREAMS=8; WRK_DUR=20; CONC=50
for a in "$@"; do case "$a" in
  --quick) SIZE_MB=50;  WINDOW=8;  WRK_DUR=8  ;;
  --long)  SIZE_MB=200; WINDOW=60; WRK_DUR=45 ;;
  --window) WINDOW="$2"; WRK_DUR="$2"; shift ;;
  --size)   SIZE_MB="$2"; shift ;;
  --streams) STREAMS="$2"; shift ;;
esac; done
FILE_BYTES=$((SIZE_MB*1024*1024))

B="\033[1m"; G="\033[92m"; CY="\033[96m"; Y="\033[93m"; R="\033[91m"; M="\033[95m"; Z="\033[0m"
C(){ sudo ip netns exec client_ns "$@"; }
hr(){ printf "${B}${CY}%s${Z}\n" "=================================================================================="; }
banner(){ echo; hr; printf "${B}${CY}  %s${Z}\n" "$*"; hr; }
sec(){ echo; printf "${B}${M}▶ %s${Z}\n" "$*"; }
info(){ printf "  ${CY}ℹ${Z} %s\n" "$*"; }
ok(){ printf "  ${G}✔${Z} %s\n" "$*"; }
warn(){ printf "  ${Y}!${Z} %s\n" "$*"; }

banner "Aethon vs Nginx — Honest Same-Wire Sustained Benchmark"
printf "  Window: ${B}%ss${Z} per measurement | File: ${B}%s MB${Z} | Streams: ${B}%s${Z} | 1500 MTU, offloads off, both over the veth\n" "$WINDOW" "$SIZE_MB" "$STREAMS"

[[ $EUID -eq 0 ]] || { printf "${R}Run as root: sudo %s${Z}\n" "$0"; exit 1; }
pgrep -f afxdp_control >/dev/null || { printf "${R}Aethon not running: sudo ./build/src/afxdp_control veth0${Z}\n"; exit 1; }
if ! C curl -fsS "$N_HTTP/api/health" >/dev/null 2>&1; then
  printf "${R}Fair baseline %s unreachable — restart the stack so nginx gets the 8081/8444 listeners:${Z}\n" "$N_HTTP"
  echo  "    tests/web_app_test/stop.sh ; tests/web_app_test/start.sh ; then restart Aethon"
  exit 1
fi
C ethtool -K veth1 gro off gso off tso off tx off rx off >/dev/null 2>&1 || true
ethtool -K veth0 gro off gso off tso off tx off rx off >/dev/null 2>&1 || true
T="$RUN_DIR/files/${SIZE_MB}mb.bin"
if [[ ! -f "$T" || $(stat -c%s "$T" 2>/dev/null) -ne "$FILE_BYTES" ]]; then
  info "Generating ${SIZE_MB} MB payload..."; mkdir -p "$RUN_DIR/files"; command head -c "$FILE_BYTES" /dev/urandom > "$T"
fi
# Guard: make sure the payload is actually the size we expect and nginx can read it
ACTUAL=$(stat -c%s "$T" 2>/dev/null || echo 0)
if [[ "$ACTUAL" -ne "$FILE_BYTES" ]]; then
  printf "${R}Payload generation failed: %s is %s bytes, expected %s. Check free space (df -h /tmp).${Z}\n" "$T" "$ACTUAL" "$FILE_BYTES"; exit 1
fi
chmod 644 "$T" 2>/dev/null || true
info "Payload ready ($(sha256sum "$T" | cut -c1-16)...)"

FILE_URL="/files/${SIZE_MB}mb.bin"

# Sustained single stream for WINDOW sec; echo "MBps Gbps".
#   $1 runner ("" host | "C" ns), $2 url, $3.. extra curl args (e.g. --resolve ...)
sustain_one(){
  local run="$1" url="$2"; shift 2
  local t0 now sz bytes=0 t1
  t0=$(date +%s%N)
  while :; do
    now=$(date +%s%N); (( now - t0 >= WINDOW*1000000000 )) && break
    sz=$($run curl -sk "$@" -o /dev/null -w '%{size_download}' "$url" 2>/dev/null || echo 0)
    bytes=$(( bytes + sz ))
  done
  t1=$(date +%s%N)
  awk -v b="$bytes" -v s="$t0" -v e="$t1" 'BEGIN{d=(e-s)/1e9; printf "%.1f %.2f",(b/1048576)/d,(b*8/1e9)/d}'
}
# Sustained N parallel streams for WINDOW sec; echo "MBps Gbps". Same args as sustain_one.
sustain_par(){
  local run="$1" url="$2"; shift 2
  local tmp i t0 t1 total=0 f
  tmp=$(mktemp -d); t0=$(date +%s%N)
  for ((i=0;i<STREAMS;i++)); do
    ( local e b s
      e=$(( $(date +%s%N) + WINDOW*1000000000 )); b=0
      while (( $(date +%s%N) < e )); do
        s=$($run curl -sk "$@" -o /dev/null -w '%{size_download}' "$url" 2>/dev/null || echo 0); b=$(( b + s ))
      done
      echo "$b" > "$tmp/w$i" ) &
  done
  wait; t1=$(date +%s%N)
  for f in "$tmp"/w*; do total=$(( total + $(cat "$f") )); done
  rm -rf "$tmp"
  awk -v b="$total" -v s="$t0" -v e="$t1" 'BEGIN{d=(e-s)/1e9; printf "%.1f %.2f",(b/1048576)/d,(b*8/1e9)/d}'
}
pct(){ awk -v a="$1" -v n="$2" 'BEGIN{ if(n>0)printf "%d%%",0.5+100*a/n; else print "-" }'; }

# ---- HTTP -------------------------------------------------------------------
sec "Phase 1 — Plain HTTP (same wire, ${WINDOW}s windows)"
info "nginx single-stream (${WINDOW}s)...";  read -r H_N_MB  H_N_G  <<<"$(sustain_one C "$N_HTTP$FILE_URL")"
info "Aethon single-stream (${WINDOW}s)...";  read -r H_A_MB  H_A_G  <<<"$(sustain_one C "$A_HTTP$FILE_URL")"
ok "nginx : ${H_N_MB} MB/s (${H_N_G} Gbps)";  ok "Aethon: ${H_A_MB} MB/s (${H_A_G} Gbps)  ->  $(pct "$H_A_MB" "$H_N_MB") of nginx"
info "nginx ${STREAMS}-stream (${WINDOW}s)..."; read -r H_NM_MB H_NM_G <<<"$(sustain_par C "$N_HTTP$FILE_URL")"
info "Aethon ${STREAMS}-stream (${WINDOW}s)..."; read -r H_AM_MB H_AM_G <<<"$(sustain_par C "$A_HTTP$FILE_URL")"
ok "nginx : ${H_NM_MB} MB/s (${H_NM_G} Gbps)"; ok "Aethon: ${H_AM_MB} MB/s (${H_AM_G} Gbps)  ->  $(pct "$H_AM_MB" "$H_NM_MB") of nginx"

# ---- HTTPS ------------------------------------------------------------------
sec "Phase 2 — HTTPS / TLS 1.3 (same wire, ${WINDOW}s windows)"
# Aethon TLS routes by SNI, so hit https://test.local with --resolve to the server IP.
TLS_RESOLVE=(--resolve "$TLS_HOST:443:$SERVER_IP")
A_HTTPS="https://$TLS_HOST$FILE_URL"
info "nginx single-stream (${WINDOW}s)...";  read -r S_N_MB  S_N_G  <<<"$(sustain_one C "$N_HTTPS$FILE_URL")"
info "Aethon single-stream (${WINDOW}s)...";  read -r S_A_MB  S_A_G  <<<"$(sustain_one C "$A_HTTPS" "${TLS_RESOLVE[@]}")"
ok "nginx : ${S_N_MB} MB/s (${S_N_G} Gbps)";  ok "Aethon: ${S_A_MB} MB/s (${S_A_G} Gbps)  ->  $(pct "$S_A_MB" "$S_N_MB") of nginx"
info "nginx ${STREAMS}-stream (${WINDOW}s)..."; read -r S_NM_MB S_NM_G <<<"$(sustain_par C "$N_HTTPS$FILE_URL")"
info "Aethon ${STREAMS}-stream (${WINDOW}s)..."; read -r S_AM_MB S_AM_G <<<"$(sustain_par C "$A_HTTPS" "${TLS_RESOLVE[@]}")"
ok "nginx : ${S_NM_MB} MB/s (${S_NM_G} Gbps)"; ok "Aethon: ${S_AM_MB} MB/s (${S_AM_G} Gbps)  ->  $(pct "$S_AM_MB" "$S_NM_MB") of nginx"

# ---- transaction rate (wrk) -------------------------------------------------
HR_N="n/a"; HR_A="n/a"; TR_N="n/a"; TR_A="n/a"
if command -v wrk >/dev/null 2>&1; then
  sec "Phase 3 — Small-request transaction rate (wrk, ${WRK_DUR}s)"
  info "HTTP  nginx..."; HR_N=$(C wrk -t2 -c$CONC -d${WRK_DUR}s "$N_HTTP/api/health" 2>/dev/null|awk '/Requests\/sec/{print $2}')
  info "HTTP  Aethon..."; HR_A=$(C wrk -t2 -c$CONC -d${WRK_DUR}s "$A_HTTP/api/health" 2>/dev/null|awk '/Requests\/sec/{print $2}')
  ok "nginx ${HR_N:-n/a} req/s  |  Aethon ${HR_A:-n/a} req/s"
  info "HTTPS nginx..."; TR_N=$(C wrk -t2 -c$((CONC/2)) -d${WRK_DUR}s "$N_HTTPS/api/health" 2>/dev/null|awk '/Requests\/sec/{print $2}')
  info "HTTPS Aethon..."; TR_A=$(C wrk -t2 -c$((CONC/2)) -d${WRK_DUR}s -H "Host: $TLS_HOST" "https://$SERVER_IP/api/health" 2>/dev/null|awk '/Requests\/sec/{print $2}')
  ok "nginx ${TR_N:-n/a} req/s  |  Aethon ${TR_A:-n/a} req/s"
fi

# ---- loopback reference -----------------------------------------------------
sec "Reference — nginx over loopback (kernel fast-path ceiling, NOT like-for-like)"
read -r LO_H_MB LO_H_G <<<"$(sustain_one '' "$LO_HTTP$FILE_URL")"
read -r LO_S_MB LO_S_G <<<"$(sustain_one '' "$LO_HTTPS$FILE_URL")"
warn "loopback HTTP : ${LO_H_MB} MB/s (${LO_H_G} Gbps)   [sendfile+TSO, 64 KB segments]"
warn "loopback HTTPS: ${LO_S_MB} MB/s (${LO_S_G} Gbps)"

# ---- matrix -----------------------------------------------------------------
banner "Results — same wire (client_ns -> veth, 1500 MTU, offloads off, ${WINDOW}s windows)"
printf "${B}%-22s | %13s | %13s | %13s | %8s${Z}\n" "Metric" "nginx MB/s" "nginx Gbps" "Aethon MB/s" "Aethon%"
printf -- "-----------------------+---------------+---------------+---------------+---------\n"
row(){ printf "%-22s | %13s | %13s | %13s | ${G}%7s${Z}\n" "$1" "$2" "$3" "$4" "$(pct "$5" "$2")"; }
row "HTTP  1-stream"          "$H_N_MB"  "$H_N_G"  "$H_A_MB"  "$H_A_MB"
row "HTTP  ${STREAMS}-stream" "$H_NM_MB" "$H_NM_G" "$H_AM_MB" "$H_AM_MB"
row "HTTPS 1-stream"          "$S_N_MB"  "$S_N_G"  "$S_A_MB"  "$S_A_MB"
row "HTTPS ${STREAMS}-stream" "$S_NM_MB" "$S_NM_G" "$S_AM_MB" "$S_AM_MB"
printf -- "-----------------------+---------------+---------------+---------------+---------\n"
printf "%-22s | %13s | %13s | %13s |\n" "HTTP  req/s (wrk)"  "${HR_N:-n/a}" "" "${HR_A:-n/a}"
printf "%-22s | %13s | %13s | %13s |\n" "HTTPS req/s (wrk)"  "${TR_N:-n/a}" "" "${TR_A:-n/a}"
printf -- "-----------------------+---------------+---------------+---------------+---------\n"
printf "%-22s | %13s | %13s | %13s |\n" "nginx LOOPBACK HTTP"  "$LO_H_MB"  "$LO_H_G"  "(ceiling)"
printf "%-22s | %13s | %13s | %13s |\n" "nginx LOOPBACK HTTPS" "$LO_S_MB"  "$LO_S_G"  "(ceiling)"

echo
printf "${B}How to read this:${Z}\n"
echo  "  • nginx and Aethon rows are the SAME path (veth, 1500 MTU, offloads off); the Aethon% column"
echo  "    is Aethon's share of same-wire nginx — the real cost of its userspace TCP + TLS + DPI."
echo  "  • Each number is sustained over a ${WINDOW}s window, not a single burst."
echo  "  • Aethon also runs full reassembly, TLS termination and 6,600+ Hyperscan rules that nginx does not."
echo  "  • The LOOPBACK rows are nginx's kernel fast-path (sendfile+TSO, 64 KB) — context only, never quote"
echo  "    them as 'Aethon vs nginx'."
echo
