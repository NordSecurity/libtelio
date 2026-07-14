#!/usr/bin/env bash
#
# Wait until a nat-lab guest VM is reachable over SSH, then exit 0. If it never
# becomes reachable within the timeout, exit non-zero.
#
# Why this exists
# ---------------
# A guest's sshd reports "running" (Windows) / "On" (macOS) / "active" (Linux)
# slightly BEFORE its listener is actually bound to the port. During that window
# the container looks healthy but the test runner's SSH to the guest LAN IP is
# refused -- which used to abort the whole pytest session with an INTERNALERROR.
#
# So every VM entrypoint calls this before signalling readiness. dockur only
# writes /ready (the healthcheck marker) when the entrypoint exits 0, so timing
# out here keeps the VM "unhealthy" at bring-up instead of failing a test later.
#
# All three per-OS checks live here, in one place, so the entrypoints stay a
# single line: `wait_for_guest_ssh.sh <windows|mac|linux> [timeout_secs]`.

set -euo pipefail

os="${1:?usage: wait_for_guest_ssh.sh <windows|mac|linux> [timeout_secs]}"
timeout_secs="${2:-120}"
interval_secs=2

case "$os" in
    windows | mac | linux) ;;
    *) echo "unknown OS '$os' (expected windows|mac|linux)" >&2; exit 64 ;;
esac

# --- readiness probes --------------------------------------------------------
#
# Each probe runs INSIDE the guest via the QEMU guest agent (qga.py). It must
# exit 0 ONLY when SSH is truly reachable: first a cheap service-state check,
# then a real TCP connect to 127.0.0.1:22 (the check that actually caught the
# race). Distinct non-zero codes make boot logs easy to read:
#   2 = sshd service not up      3 = probe tool missing
#   4 = service up but :22 not accepting yet

probe_windows() {
    # PowerShell is always present on the Windows guest; Test-NetConnection does
    # the TCP connect. -InformationLevel Quiet returns a bare $true/$false.
    python3 /run/qga.py powershell -Command '
        $svc = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
        if ($null -eq $svc)          { Write-Output "sshd service not found";       exit 3 }
        if ($svc.Status -ne "Running") { Write-Output ("sshd status: " + $svc.Status); exit 2 }
        if (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            Write-Output "sshd not accepting on :22 yet"; exit 4
        }
        Write-Output "sshd running and accepting on :22"; exit 0
    '
}

probe_mac() {
    # systemsetup reports the Remote Login (SSH) toggle; nc does the TCP connect
    # (-G is the connect timeout on macOS nc, which is always present).
    python3 /run/qga.py --sh '
        command -v systemsetup >/dev/null 2>&1 || { echo "systemsetup not found"; exit 3; }
        /usr/sbin/systemsetup -getremotelogin 2>/dev/null | grep -q "On" || { echo "Remote Login (SSH) is Off"; exit 2; }
        nc -z -G 2 127.0.0.1 22 >/dev/null 2>&1 || { echo "SSH not accepting on :22 yet"; exit 4; }
        echo "Remote Login (SSH) on and accepting on :22"; exit 0
    '
}

probe_linux() {
    # systemctl (or pgrep fallback) for the service; nc for the TCP connect
    # (-w is the connect timeout on Linux nc). nc is not guaranteed on every
    # Linux guest, so the connect check is skipped when nc is absent rather than
    # deadlocking -- the service check remains the floor.
    python3 /run/qga.py --sh '
        if command -v systemctl >/dev/null 2>&1; then
            systemctl is-active --quiet sshd || systemctl is-active --quiet ssh || { echo "SSH service not active"; exit 2; }
        else
            pgrep -x sshd >/dev/null 2>&1 || { echo "sshd process not running"; exit 2; }
        fi
        if command -v nc >/dev/null 2>&1 && ! nc -z -w2 127.0.0.1 22; then
            echo "SSH not accepting on :22 yet"; exit 4
        fi
        echo "SSH active and accepting on :22"; exit 0
    '
}

probe_once() {
    case "$os" in
        windows) probe_windows ;;
        mac)     probe_mac ;;
        linux)   probe_linux ;;
    esac
}

# --- retry loop --------------------------------------------------------------
#
# Poll until the probe succeeds or the deadline passes. A failing probe is
# normal during boot, so we capture its exit code, log it, and retry; only a
# real timeout is fatal (and carries the last probe's code out to the caller).

end=$((SECONDS + timeout_secs))
last_rc=1

while [ "$SECONDS" -lt "$end" ]; do
    if output=$(probe_once); then
        echo "$output"
        exit 0
    else
        last_rc=$?
        echo "$output"
        echo "[$os] SSH not ready yet (rc=$last_rc); retrying in ${interval_secs}s..."
        sleep "$interval_secs"
    fi
done

echo "[$os] timed out waiting for guest SSH on :22 after ${timeout_secs}s"
exit "$last_rc"
