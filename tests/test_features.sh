#!/usr/bin/env bash
# ==============================================================================
#  Aethon functional feature tests — run through the veth, from client_ns.
#  Covers: HTTP, HTTPS/TLS termination, SNI routing, SNI blocklist, 502 on dead
#  backend, payload integrity, concurrency, and a (soft) DPI probe.
#  Needs: root + running Aethon on veth0 + web stack (nginx+node).
#    sudo ./tests/test_features.sh
# ==============================================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
SERVER_IP="192.168.50.1"
TLS_HOST="test.local"
G="\033[92m"; R="\033[91m"; Y="\033[93m"; B="\033[1m"; Z="\033[0m"
C(){ sudo ip netns exec client_ns "$@"; }
PASS=0; FAIL=0
ok(){ printf "  ${G}✔${Z} %s\n" "$1"; PASS=$((PASS+1)); }
no(){ printf "  ${R}✗${Z} %s\n" "$1"; FAIL=$((FAIL+1)); }
soft(){ printf "  ${Y}•${Z} %s\n" "$1"; }
# expect success:
want_ok(){ local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else no "$d"; fi; }
# expect failure (blocked / reset / timeout):
want_blk(){ local d="$1"; shift; if "$@" >/dev/null 2>&1; then no "$d — expected block, but it succeeded"; else ok "$d"; fi; }

printf "${B}Aethon functional feature tests${Z}\n"
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0"; exit 1; }
pgrep -x afxdp_control >/dev/null || { printf "${R}Aethon not running (sudo ./build/src/afxdp_control veth0)${Z}\n"; exit 1; }
C curl -fsS "http://$SERVER_IP/api/health" >/dev/null 2>&1 || { printf "${R}Stack not reachable through Aethon — start web stack + Aethon first${Z}\n"; exit 1; }

CURL=(curl -s --max-time 10)
CURLK=(curl -sk --max-time 10)

printf "\n${B}1) Transport / TLS${Z}\n"
want_ok "HTTP GET through Aethon (200)"           C "${CURL[@]}"  -f "http://$SERVER_IP/api/health"
want_ok "HTTPS TLS termination (test.local)"      C "${CURLK[@]}" -f --resolve "$TLS_HOST:443:$SERVER_IP" "https://$TLS_HOST/api/health"
want_ok "HTTP static file serves"                 C "${CURL[@]}"  -f "http://$SERVER_IP/files/5mb.bin" -o /dev/null

printf "\n${B}2) SNI routing${Z}\n"
want_ok "SNI route: mydomain.com -> backend"      C "${CURLK[@]}" -f --resolve "mydomain.com:443:$SERVER_IP" "https://mydomain.com/api/health"
want_ok "SNI route: api.mydomain.com -> backend"  C "${CURLK[@]}" -f --resolve "api.mydomain.com:443:$SERVER_IP" "https://api.mydomain.com/api/health"
# auth.mydomain.com maps to backend port 5000 which isn't running -> expect a gateway error, not a crash
if out=$(C "${CURLK[@]}" -o /dev/null -w '%{http_code}' --resolve "auth.mydomain.com:443:$SERVER_IP" "https://auth.mydomain.com/api/health" 2>/dev/null); then
  [[ "$out" == "502" || "$out" == "503" || "$out" == "504" ]] && ok "Dead backend (auth:5000) -> $out gateway error" || soft "auth.mydomain.com returned $out (backend may be up)"
else soft "auth.mydomain.com connection closed (acceptable for a dead backend)"; fi

printf "\n${B}3) SNI blocklist (should be reset at wire speed)${Z}\n"
want_blk "Blocked SNI malicious.test.com reset"   C "${CURLK[@]}" -f --resolve "malicious.test.com:443:$SERVER_IP" "https://malicious.test.com/"
want_blk "Blocked SNI c2-botnet.net reset"        C "${CURLK[@]}" -f --resolve "c2-botnet.net:443:$SERVER_IP" "https://c2-botnet.net/"

printf "\n${B}4) Payload integrity (bytes survive reassembly + proxy)${Z}\n"
SRC="$RUN_DIR/files/5mb.bin"
if [[ -f "$SRC" ]]; then
  src_sha=$(sha256sum "$SRC" | cut -d' ' -f1)
  dl=$(mktemp); C "${CURL[@]}" "http://$SERVER_IP/files/5mb.bin" -o "$dl" 2>/dev/null
  dl_sha=$(sha256sum "$dl" 2>/dev/null | cut -d' ' -f1); rm -f "$dl"
  [[ "$src_sha" == "$dl_sha" && -n "$src_sha" ]] && ok "5 MB download SHA256 matches origin" || no "5 MB download corrupted (sha mismatch)"
else soft "skipped integrity test (no $SRC — run the speed test once to generate it)"; fi

printf "\n${B}5) Concurrency (20 parallel requests all succeed)${Z}\n"
pids=(); bad=0
for i in $(seq 1 20); do C "${CURL[@]}" -f "http://$SERVER_IP/api/health" >/dev/null 2>&1 & pids+=($!); done
for p in "${pids[@]}"; do wait "$p" || bad=$((bad+1)); done
[[ $bad -eq 0 ]] && ok "20/20 concurrent requests OK" || no "$bad/20 concurrent requests failed"

printf "\n${B}6) DPI probe (soft — depends on loaded rule set)${Z}\n"
# Send a classic attack signature; if a matching DPI rule is loaded, Aethon resets the flow.
if C "${CURL[@]}" -f "http://$SERVER_IP/?id=1%20UNION%20SELECT%20password%20FROM%20users" >/dev/null 2>&1; then
  soft "SQLi-style request not blocked (no matching rule loaded — not a failure)"
else
  ok "SQLi-style request blocked by DPI"
fi

printf "\n${B}Result:${Z} ${G}%d passed${Z}, ${R}%d failed${Z}\n" "$PASS" "$FAIL"
exit $(( FAIL > 0 ? 1 : 0 ))
