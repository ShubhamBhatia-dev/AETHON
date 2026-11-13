#!/bin/bash
# ==============================================================================
# Aethon Standalone Fail-Open Watchdog Daemon
#
# Monitors afxdp_control. If the process is dead while an XDP program is still
# attached to the physical interface, it immediately detaches XDP to restore
# normal Linux kernel packet flow.
# ==============================================================================

set -euo pipefail

ENV_FILE="/etc/aethon/aethon.env"
if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${ENV_FILE}"
fi

IFACE="${IFACE:-eth0}"
CHECK_INTERVAL_SEC=1

log() {
    echo "[$(date -u +'%Y-%m-%d %H:%M:%SZ')] [Aethon Watchdog] $*"
}

detach_xdp() {
    log "EMERGENCY: afxdp_control is dead but XDP is attached to ${IFACE}! Detaching XDP to fail open..."
    ip link set dev "${IFACE}" xdp off || true
    log "XDP detached. Kernel network stack restored on ${IFACE}."
}

is_xdp_attached() {
    ip link show dev "${IFACE}" 2>/dev/null | grep -q "xdp"
}

is_aethon_alive() {
    pgrep -x "afxdp_control" >/dev/null 2>&1
}

# Verification test mode for CI / Test environments
if [[ "${1:-}" == "--test" ]]; then
    log "Running watchdog verification check on interface ${IFACE}..."
    if is_xdp_attached; then
        log "XDP is currently attached to ${IFACE}."
        if is_aethon_alive; then
            log "afxdp_control process is healthy."
        else
            log "WARNING: XDP attached but process not found!"
            detach_xdp
        fi
    else
        log "XDP is not currently attached to ${IFACE}."
    fi
    exit 0
fi

log "Starting Aethon Fail-Open Watchdog on interface ${IFACE} (check interval: ${CHECK_INTERVAL_SEC}s)..."

while true; do
    if is_xdp_attached; then
        if ! is_aethon_alive; then
            detach_xdp
        fi
    fi
    sleep "${CHECK_INTERVAL_SEC}"
done
