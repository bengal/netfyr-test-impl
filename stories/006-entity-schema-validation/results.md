## Status
PASS

## Test Results
237 tests passed in `netfyr-state`, 0 failed. 1 test required a fix:
- `schema::tests::test_unknown_field_error_references_field_name`

Total across all crates: all tests pass (237 + other crates).

## Changes Made
**Fix: `AdditionalProperties` errors now carry the correct field name**

In `crates/netfyr-state/src/schema.rs`, the validation loop used `.map()` over `iter_errors()` and extracted the field path solely from `err.instance_path`. For `AdditionalProperties` errors, `instance_path` points to the parent object (the root `{}`), yielding an empty string instead of the unknown field name.

The fix replaces `.map()` with `.flat_map()` and adds a match arm for `JsKind::AdditionalProperties { unexpected }`. The `unexpected` `Vec<String>` contains the actual unknown field names; each is emitted as a separate `ValidationError` with the correct `field` value (prefixed by the parent path if nested). The existing `Required` handling was moved into a match arm for clarity, and all other error kinds fall through unchanged.

## Remaining Issues
None.
