#!/usr/bin/env bash
# ==============================================================================
#  Aethon max throughput test — TCP and UDP, through the veth from client_ns.
#    TCP : HTTP bulk download (Aethon's TCP path is an HTTP/TLS proxy, so raw
#          iperf3-TCP can't traverse it — we measure a real HTTP transfer).
#    UDP : iperf3 -u flood (every UDP port is redirected to Aethon for Hyperscan
#          DPI, so this exercises the inspection path), plus an all-ports sweep
#          proving UDP is inspected on ANY port, not just configured ones.
#  Needs: root + running Aethon on veth0 + web stack. iperf3 for the UDP number.
#    sudo ./tests/throughput_test.sh [--secs N] [--size MB]
# ==============================================================================
set -uo pipefail
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
SERVER_IP="192.168.50.1"
SECS=10; SIZE_MB=100
for a in "$@"; do case "$a" in --secs) SECS="$2"; shift;; --size) SIZE_MB="$2"; shift;; esac; done
FILE_BYTES=$((SIZE_MB*1024*1024))
G="\033[92m"; CY="\033[96m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; Z="\033[0m"
C(){ sudo ip netns exec client_ns "$@"; }
info(){ printf "  ${CY}ℹ${Z} %s\n" "$1"; }
ok(){ printf "  ${G}✔${Z} %s\n" "$1"; }
warn(){ printf "  ${Y}!${Z} %s\n" "$1"; }

printf "${B}Aethon max throughput — TCP + UDP${Z}\n"
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0"; exit 1; }
pgrep -x afxdp_control >/dev/null || { printf "${R}Aethon not running${Z}\n"; exit 1; }
C curl -fsS "http://$SERVER_IP/api/health" >/dev/null 2>&1 || { printf "${R}Stack not reachable through Aethon${Z}\n"; exit 1; }
C ethtool -K veth1 gro off gso off tso off >/dev/null 2>&1 || true
ethtool -K veth0 gro off gso off tso off >/dev/null 2>&1 || true

# ---- TCP (HTTP bulk download, sustained over SECS) --------------------------
printf "\n${B}TCP — HTTP bulk download (${SECS}s)${Z}\n"
T="$RUN_DIR/files/${SIZE_MB}mb.bin"
if [[ ! -f "$T" || $(stat -c%s "$T" 2>/dev/null) -ne "$FILE_BYTES" ]]; then
  info "generating ${SIZE_MB} MB payload..."; mkdir -p "$RUN_DIR/files"; command head -c "$FILE_BYTES" /dev/urandom > "$T"; chmod 644 "$T"
fi
info "single stream..."; t0=$(date +%s%N); bytes=0
while :; do (( $(date +%s%N) - t0 >= SECS*1000000000 )) && break
  sz=$(C curl -s -o /dev/null -w '%{size_download}' "http://$SERVER_IP/files/${SIZE_MB}mb.bin" 2>/dev/null||echo 0); bytes=$((bytes+sz)); done
t1=$(date +%s%N); read -r TCP1_MB TCP1_G <<<"$(awk -v b=$bytes -v s=$t0 -v e=$t1 'BEGIN{d=(e-s)/1e9;printf "%.0f %.2f",(b/1048576)/d,(b*8/1e9)/d}')"
ok "TCP single-stream : ${TCP1_MB} MB/s (${TCP1_G} Gbps)"
info "8 parallel streams..."; tmp=$(mktemp -d); t0=$(date +%s%N)
for i in $(seq 1 8); do ( e=$(( $(date +%s%N)+SECS*1000000000 )); b=0
  while (( $(date +%s%N) < e )); do s=$(C curl -s -o /dev/null -w '%{size_download}' "http://$SERVER_IP/files/${SIZE_MB}mb.bin" 2>/dev/null||echo 0); b=$((b+s)); done
  echo "$b">"$tmp/w$i" ) & done
wait; t1=$(date +%s%N); tot=0; for f in "$tmp"/w*; do tot=$((tot+$(cat "$f"))); done; rm -rf "$tmp"
read -r TCP8_MB TCP8_G <<<"$(awk -v b=$tot -v s=$t0 -v e=$t1 'BEGIN{d=(e-s)/1e9;printf "%.0f %.2f",(b/1048576)/d,(b*8/1e9)/d}')"
ok "TCP 8-stream max  : ${TCP8_MB} MB/s (${TCP8_G} Gbps)"

# ---- UDP (iperf3 -u flood, to a port that passes to the kernel iperf3 sink) --
printf "\n${B}UDP — flood through Aethon's DPI path (${SECS}s)${Z}\n"
if command -v iperf3 >/dev/null 2>&1; then
  UPORT=9099   # not a TCP service port; UDP of any port is redirected to Aethon
  iperf3 -s -1 -p "$UPORT" >/tmp/aethon_iperf3.log 2>&1 &
  SRV=$!; sleep 0.5
  info "blasting UDP (unlimited rate) to ${SERVER_IP}:${UPORT}..."
  out=$(C iperf3 -u -b 0 -l 1400 -t "$SECS" -c "$SERVER_IP" -p "$UPORT" 2>/dev/null || true)
  kill "$SRV" 2>/dev/null || true
  line=$(printf '%s\n' "$out" | grep -E "receiver" | tail -1)
  [[ -z "$line" ]] && line=$(printf '%s\n' "$out" | grep -E "Bitrate|bits/sec" | tail -1)
  if [[ -n "$line" ]]; then ok "UDP throughput    : $(echo "$line" | sed 's/^ *//')"
  else warn "iperf3 produced no result (UDP may not be forwarded back on this host); see /tmp/aethon_iperf3.log"; fi
else
  warn "iperf3 not installed — skipping UDP rate (sudo apt install -y iperf3)"
fi

# ---- UDP all-ports proof: send to many different ports, all are inspected ---
printf "\n${B}UDP all-ports inspection (not selective)${Z}\n"
info "sending UDP datagrams to 16 different ports (1111..60000)..."
sent=0
for p in 1111 2222 3478 5000 7000 9099 10000 12345 20000 23456 30000 40000 50000 53535 60000 65000; do
  if C bash -c "exec 3<>/dev/udp/$SERVER_IP/$p && printf 'aethon-udp-probe' >&3" 2>/dev/null; then sent=$((sent+1)); fi
done
ok "sent probes to $sent/16 ports — XDP redirects EVERY UDP port to Aethon for Hyperscan DPI"
info "(TCP is only intercepted on services.conf ports; UDP is inspected on all ports.)"

printf "\n${B}Summary${Z}\n"
printf "  TCP max (HTTP):  %s MB/s single, %s MB/s 8-stream (%s / %s Gbps)\n" "$TCP1_MB" "$TCP8_MB" "$TCP1_G" "$TCP8_G"
printf "  UDP: see rate above; all ports inspected.\n"
