## Status
PASS

## Test Results
All 209 tests pass (178 in netfyr-state, 17 in entity_state_types integration tests, 14 in workspace_setup). No tests skipped.

Two tests required fixes:
- `yaml::tests::test_deserialize_value_ip_addr_string_becomes_ip_addr`
- `yaml::tests::test_round_trip_yaml_ip_addr_becomes_ip_network_bug`

## Changes Made

**Fix 1: `crates/netfyr-state/src/yaml.rs` — IP address deserialization heuristic**

The `deserialize_value` function tried `IpNetwork::from_str` before `IpAddr::from_str`. The code comment claimed the `ipnetwork` crate requires a `/prefix` and would fail on bare IPs, but that is incorrect — `ipnetwork` accepts bare IP addresses and promotes them to host-route networks (e.g., `"10.0.1.1"` → `Ipv4Network { addr: 10.0.1.1, prefix: 32 }`). This caused plain IP addresses to be stored as `Value::IpNetwork` instead of `Value::IpAddr`.

Fix: gate the `IpNetwork` parse attempt behind a `s.contains('/')` check. Only strings that contain a slash are tried as CIDR networks; bare IP strings fall through to the `IpAddr` branch.

**Fix 2: `crates/netfyr-test-utils/tests/workspace_setup.rs` — expected source file list**

The `test_no_extraneous_source_files_in_library_crates` test was written before SPEC-005 and listed only `["diff.rs", "lib.rs", "set.rs"]` for `netfyr-state`. SPEC-005 added `loader.rs` and `yaml.rs` to that crate; the expected list was updated to `["diff.rs", "lib.rs", "loader.rs", "set.rs", "yaml.rs"]`.

## Remaining Issues
None.
