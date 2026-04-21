# Gap Analysis: SPEC-354 State Revert

## Current State

### Journal infrastructure (complete)
- `netfyr-journal/src/entry.rs`: `Trigger::Revert { target_seq: SequenceId }` variant already exists and is tested. `JournalEntry`, `ApplyOutcome`, `summarize_policies` are all in place.
- `netfyr-journal/src/serializable.rs`: `SerializableStateSet` and `SerializableState` exist with a `From<&StateSet>` impl. **No `to_state_set()` reverse conversion exists** — this is the primary gap in this crate.
- `netfyr-journal/src/journal.rs`: `Journal::open_default()`, `read_entry(seq)`, `append()` are all available.

### Daemon server (partial)
- `netfyr-daemon/src/server.rs`: `server_trigger_type_str` already handles `Trigger::Revert { .. } => "revert"` (dead branch until the handler exists). The `match method.as_str()` dispatch does **not** include `"io.netfyr.Revert"`.
- Existing handlers (`handle_submit_policies`, `handle_dry_run`, `handle_query`) provide the implementation pattern.

### CLI (absent)
- `netfyr-cli/src/lib.rs`: `Commands` enum has `Apply`, `Query`, `History` — no `Revert` variant.
- No `crates/netfyr-cli/src/revert.rs` file exists.
- `apply.rs` provides the daemon-detection and exit-code patterns to follow.

### Varlink client (absent)
- `netfyr-varlink/src/client.rs`: No `revert()` method exists on `VarlinkClient`.

### Value type conversion
- `netfyr-varlink/src/types.rs`: `json_to_value(v: serde_json::Value) -> Result<Value, String>` exists but lives in a crate that `netfyr-journal` does not depend on.
- `netfyr-state/src/yaml.rs`: `deserialize_value` takes `serde_yaml::Value`, not `serde_json::Value` — cannot be reused directly.
- No JSON-to-`netfyr_state::Value` conversion exists in `netfyr-state` itself.

---

## Requirements

1. **`SerializableStateSet::to_state_set()`** — convert a stored snapshot back to a live `StateSet`. Must handle all `Value` variants: `U64`, `I64`, `Bool`, `String`, `Ipv4Addr`, `Ipv4Network`, lists, maps. Provenance for all restored fields is `Provenance::UserConfigured { policy_ref: "revert".into() }`.

2. **`crates/netfyr-cli/src/revert.rs`** — new module implementing:
   - `pub struct RevertArgs { pub target: u64, pub dry_run: bool }`
   - `pub async fn run_revert(args: RevertArgs) -> Result<ExitCode>`
   - Daemon-detection: try `VarlinkClient::connect`; on `ConnectionFailed` fall back to local mode.
   - Local mode: open journal → read entry → call `to_state_set()` → `BackendRegistry::query_all()` → `generate_diff()` → conditionally apply → conditionally append journal entry.
   - Daemon mode: call `client.revert(target, dry_run)` → display report → print policy-drift warning to stderr.
   - "Entry not found" exits with code 1.
   - "No changes needed" exits with code 0.
   - Partial failure exits with non-zero code (matching `apply` behavior).

3. **`crates/netfyr-cli/src/lib.rs`** — add `Revert(revert::RevertArgs)` to `Commands`; expose `pub mod revert` and `pub use revert::run_revert`.

4. **`crates/netfyr-cli/src/main.rs`** — dispatch `Commands::Revert(args) => run_revert(args).await`.

5. **`VarlinkClient::revert()`** in `netfyr-varlink/src/client.rs` — send `io.netfyr.Revert` with `{ target_seq, dry_run }`, decode `{ report: VarlinkApplyReport }` from response.

6. **`handle_revert()`** in `netfyr-daemon/src/server.rs` — new async handler function; wire into `match method.as_str()` as `"io.netfyr.Revert"`. Must: open journal → read entry → `to_state_set()` → query current state via `reconciler.query(None, None)` → compute diff → dry-run path returns diff summary as report without applying → apply path uses backend apply → appends revert journal entry.

7. **Backend access from the daemon handler** — `handle_revert` needs to apply a pre-computed `StateDiff` directly (bypassing policy reconciliation). The current `Reconciler` API exposes `reconcile_and_apply` and `dry_run` but not a raw `apply_diff`. Either a new `Reconciler::apply_diff(diff: &StateDiff)` method is needed, or the handler calls the backend registry through the reconciler. This is the primary architectural question for the PLAN phase.

8. **Varlink interface file** — the spec mentions `crates/netfyr-varlink/src/io.netfyr.varlink`. This file does not appear in the module tree and may not exist or may not be used for code generation. The wire protocol is implemented manually; the `.varlink` file is documentation only and does not gate compilation.

---

## Gap Analysis

| Artifact | Status | Action |
|---|---|---|
| `netfyr-journal/src/serializable.rs` — `SerializableStateSet::to_state_set()` | Missing | Add method; requires JSON→Value conversion |
| JSON→`netfyr_state::Value` conversion | Missing | Add `json_to_value` to `netfyr-state` (reused by journal) **or** implement inline in `serializable.rs` using `serde_json` (already a dep of `netfyr-journal`) |
| `crates/netfyr-cli/src/revert.rs` | Missing (new file) | Create |
| `crates/netfyr-cli/src/lib.rs` — `Commands::Revert` variant | Missing | Add |
| `crates/netfyr-cli/src/main.rs` — dispatch | Missing | Add arm |
| `VarlinkClient::revert()` | Missing | Add to `netfyr-varlink/src/client.rs` |
| `handle_revert()` in `server.rs` | Missing | Add function + wire into dispatch |
| `Reconciler::apply_diff()` or equivalent | Missing or scope TBD | PLAN phase decision |
| `crates/netfyr-varlink/src/io.netfyr.varlink` | Unknown (not in module tree) | Add `Revert` method if file is maintained; otherwise skip |

---

## Integration Points

- **`Journal::open_default()` / `read_entry(seq)`** — called from CLI (local mode) and daemon handler. Already used by `handle_get_journal_entry` in `server.rs`.
- **`BackendRegistry::query_all()` and `apply()`** — called in local CLI mode via the same registry construction pattern as `apply.rs` (`NetlinkBackend` registered for `"ethernet"`).
- **`generate_diff()` from `netfyr-reconcile`** — used to compute the revert diff between target StateSet (desired) and actual StateSet (current). Signature must be verified: the "managed" entity list argument needs to be populated from the target snapshot's entities.
- **`Reconciler`** in daemon mode — `query(None, None)` to get current state; direct apply must be threaded through whatever interface exposes the backend registry. The reconciler's `set_applying(true/false)` guard should wrap the apply to suppress netlink monitor false positives.
- **`SerializableStateSet::from(&StateSet)`** — already exists; the inverse `to_state_set()` must be added alongside it.
- **`VarlinkApplyReport`** — already defined in `netfyr-varlink/src/types.rs`; the Revert Varlink method reuses it as its response type.
- **`display_apply_report()`** from `netfyr-cli/src/apply.rs` — should be reused in `revert.rs` for output formatting.
- **Exit code helpers** — `apply.rs` derives exit codes from `ApplyReport`; `revert.rs` must replicate or share this logic.

---

## Risks

1. **`Reconciler` does not expose raw apply** — `reconcile_and_apply` runs the full policy reconciliation pipeline; it cannot be used for revert. `dry_run` similarly works on a policy store. A new path to apply a pre-computed `StateDiff` is needed. Options: add `Reconciler::apply_diff`, expose the backend registry from `Reconciler`, or move the apply call to a separate utility. This is the largest architectural ambiguity.

2. **JSON→Value type heuristics** — `SerializableState::fields` stores values as raw JSON (`serde_json::Value`). Round-tripping `Ipv4Addr` ("192.168.1.1") and `Ipv4Network` ("10.0.0.0/8") requires string-parsing heuristics. If the heuristic order is wrong (e.g., tries Ipv4Network before Ipv4Addr), addresses without prefix length will be mis-typed or fail. Lists and maps of nested values add further complexity.

3. **Policy drift after daemon revert** — the spec mandates a stderr warning but does not prevent the daemon from re-applying the current (unchanged) policy set at the next reconciliation event. If a DHCP event fires immediately after a revert, the reverted state may be overwritten before the operator can act. This is accepted behavior per the spec but should be clearly communicated in the warning text.

4. **`generate_diff` managed-entities argument** — the diff function requires an explicit list of "managed" entity keys to determine what counts as a removal vs. an unmanaged entity. For revert, the managed set should be exactly the entities present in `target_state`. If the current system has additional entities not in the snapshot, the diff behavior (ignore vs. remove them) needs to be confirmed against `generate_diff`'s semantics.

5. **Journal write in daemon handler** — the daemon's `handle_*` functions currently open the journal on-demand (see `handle_get_history`). `handle_revert` must also open a mutable journal for appending, which may race with other append callers (e.g., a concurrent `reconcile_and_apply`). The journal's file-locking behavior under concurrent access needs to be verified.

6. **`RevertArgs` doc-comment scope** — the spec says per-entity filtering is not supported in this version. The CLI argument struct has no `--entity` flag, which is correct, but the doc string should make this explicit to avoid operator confusion when they expect scoped reverts.
