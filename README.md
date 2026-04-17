# netfyr

netfyr is a declarative network configuration tool for Linux. Configuration is expressed as YAML policy files; netfyr translates those policies into kernel network state via netlink. Multiple policies with overlapping fields are merged using per-field priority reconciliation, with conflicts surfaced explicitly. A long-running daemon handles dynamic factory lifecycle — for example, running a DHCPv4 client and publishing the resulting lease as network state that can be merged with static policies.

## Architecture

The project is a Rust workspace with seven crates arranged in layers:

| Crate | Role |
|---|---|
| `netfyr-state` | Core state types, selectors, values, state sets, YAML parsing, schema validation |
| `netfyr-policy` | Policy types, static and dynamic factories, YAML policy loading |
| `netfyr-reconcile` | Multi-policy reconciliation with per-field priority, conflict detection, diff generation |
| `netfyr-backend` | Backend trait and netlink implementation for querying and applying network state |
| `netfyr-varlink` | Varlink IPC protocol types and client for daemon communication |
| `netfyr-cli` | User-facing CLI binary (`netfyr`) with `apply` and `query` subcommands |
| `netfyr-daemon` | Long-running daemon for dynamic factories (DHCPv4), Varlink server, systemd integration |

Dependency flow: `netfyr-state` is the foundation. `netfyr-policy` and `netfyr-reconcile` depend on it. `netfyr-backend` depends on `netfyr-state`. `netfyr-varlink` depends on all library crates. `netfyr-cli` and `netfyr-daemon` are the top-level binaries that wire everything together.

## Usage

### Apply a policy

```yaml
# ethernet-static.yaml
kind: policy
name: eth0-static
priority: 100
factory: static
selector:
  name: eth0
state:
  ethernet:
    address: 192.168.1.10/24
    gateway: 192.168.1.1
```

```bash
netfyr apply ethernet-static.yaml
# or apply an entire directory
netfyr apply /etc/netfyr/policies/
```

### Preview changes without applying

```bash
netfyr apply --dry-run ethernet-static.yaml
```

### Query network state

```bash
# Query all current network state
netfyr query

# Query filtered by selector
netfyr query -s type=ethernet -s name=eth0

# Output as JSON
netfyr query --format json
```

### Daemon mode

`netfyr-daemon` reads policies from a directory, listens on a Varlink socket, and manages dynamic factory lifecycle (e.g., DHCPv4 clients). When the daemon is running, `netfyr apply` and `netfyr query` automatically communicate via Varlink rather than operating directly on the kernel.

```bash
# Start the daemon (reads NETFYR_POLICY_DIR, listens on NETFYR_SOCKET_PATH)
NETFYR_POLICY_DIR=/etc/netfyr/policies \
NETFYR_SOCKET_PATH=/run/netfyr/netfyr.sock \
    netfyr-daemon
```

The daemon signals systemd readiness via `sd_notify(READY=1)` when it has finished initializing. A minimal systemd unit looks like:

```ini
[Service]
ExecStart=/usr/bin/netfyr-daemon
Environment=NETFYR_POLICY_DIR=/etc/netfyr/policies
Environment=NETFYR_SOCKET_PATH=/run/netfyr/netfyr.sock
Type=notify
```

## Building

```bash
# Build all crates
cargo build

# Build a single crate
cargo build -p netfyr-state

# Build with workspace feature flags
cargo build --features dhcp,systemd
```

Workspace features: `dhcp`, `systemd`, `varlink`. These are empty feature flags used to gate optional functionality across crates.

## Testing

```bash
# Run Rust unit and integration tests
cargo test

# Run all shell integration tests (builds first)
make integration-test

# Run tests for a specific story/spec number
make integration-test SPEC=401
```

Integration tests are shell scripts in `tests/` named `NNN-description.sh`. They use `unshare --user --net` to run inside an unprivileged network namespace — no root access required. Tests follow a strict no-skip policy: if a prerequisite is missing (binary not built, `unshare` unavailable, `dnsmasq` not installed), the test prints `FAIL:` to stderr and exits 1. It never exits 0 on a missing prerequisite.

## License

See the [LICENSE](LICENSE) file for details.
