#!/bin/bash
# helpers.sh -- Shared shell functions for netfyr integration tests.
# Source this file from test scripts: source "$(dirname "$0")/helpers.sh"
#
# Requires: bash, ip (iproute2), unshare (util-linux), grep
# Optional: dnsmasq (only for DHCP tests)

set -euo pipefail

# Array of dnsmasq PIDs started by start_dnsmasq, used by cleanup.
_DNSMASQ_PIDS=()

# netns_setup -- Run the calling script inside a new unprivileged user+network
# namespace. Uses exec re-entry guarded by __NETNS_ENTERED to avoid recursion.
# After re-entry, registers cleanup as a trap on EXIT.
netns_setup() {
    if [[ -n "${__NETNS_ENTERED:-}" ]]; then
        # Already inside the namespace; register cleanup and continue.
        trap cleanup EXIT
        return 0
    fi

    if ! command -v unshare >/dev/null 2>&1; then
        echo "ERROR: 'unshare' not found; install util-linux to run integration tests" >&2
        exit 1
    fi

    export __NETNS_ENTERED=1
    exec unshare --user --net -- "$0" "$@"
    # exec replaces the shell; code below is unreachable.
}

# create_veth VETH0 VETH1 -- Create a veth pair and bring both ends up.
create_veth() {
    local veth0="$1"
    local veth1="$2"
    ip link add "$veth0" type veth peer name "$veth1"
    ip link set "$veth0" up
    ip link set "$veth1" up
}

# add_address IFACE CIDR -- Add an IP address to a network interface.
add_address() {
    local iface="$1"
    local cidr="$2"
    ip addr add "$cidr" dev "$iface"
}

# start_dnsmasq IFACE SERVER_IP RANGE_START RANGE_END LEASE_TIME
# Start a DHCP server on IFACE. Exits 1 immediately if dnsmasq is not installed.
# Stores the PID in _DNSMASQ_PIDS for cleanup.
start_dnsmasq() {
    local iface="$1"
    local server_ip="$2"
    local range_start="$3"
    local range_end="$4"
    local lease_time="$5"

    if ! command -v dnsmasq >/dev/null 2>&1; then
        echo "ERROR: 'dnsmasq' not found; install dnsmasq to run DHCP integration tests" >&2
        exit 1
    fi

    dnsmasq \
        --no-daemon \
        --interface="$iface" \
        --bind-interfaces \
        --listen-address="$server_ip" \
        --dhcp-range="${range_start},${range_end},${lease_time}" \
        --no-resolv \
        --no-hosts \
        --log-dhcp \
        &

    local pid=$!
    _DNSMASQ_PIDS+=("$pid")

    # Brief pause to let dnsmasq bind to the interface before tests proceed.
    sleep 1
}

# cleanup -- Kill any running dnsmasq instances started by start_dnsmasq.
# Registered as a trap EXIT handler by netns_setup.
cleanup() {
    local pid
    for pid in "${_DNSMASQ_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    _DNSMASQ_PIDS=()
}

# assert_eq ACTUAL EXPECTED MSG -- Fail if ACTUAL != EXPECTED.
assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="$3"
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: $msg: expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

# assert_match VALUE PATTERN MSG -- Fail if VALUE does not match regex PATTERN.
assert_match() {
    local value="$1"
    local pattern="$2"
    local msg="$3"
    if [[ ! "$value" =~ $pattern ]]; then
        echo "FAIL: $msg: '$value' did not match pattern '$pattern'" >&2
        exit 1
    fi
}

# assert_has_address IFACE PREFIX -- Fail if IFACE does not have an address
# containing PREFIX (e.g. "10.99.0.").
assert_has_address() {
    local iface="$1"
    local prefix="$2"
    local output
    output=$(ip addr show dev "$iface" 2>&1) || true
    if ! echo "$output" | grep -qF "$prefix"; then
        echo "FAIL: interface '$iface' does not have an address matching '$prefix'" >&2
        echo "      ip addr output: $output" >&2
        exit 1
    fi
}

# assert_link_up IFACE -- Fail if IFACE is not in the UP state.
assert_link_up() {
    local iface="$1"
    local output
    output=$(ip link show dev "$iface" 2>&1) || true
    if ! echo "$output" | grep -qE "(state UP|,UP,|<[^>]*UP[^>]*>)"; then
        echo "FAIL: interface '$iface' is not UP" >&2
        echo "      ip link output: $output" >&2
        exit 1
    fi
}
