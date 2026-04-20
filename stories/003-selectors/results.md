## Status
PASS

## Test Results
117 tests passed, 0 failed.

The previously failing test `test_no_extraneous_source_files_in_library_crates` now passes along with all others.

## Changes Made
**Inlined `selector.rs` into `lib.rs` and deleted `selector.rs`.**

The test `test_no_extraneous_source_files_in_library_crates` asserts that `netfyr-state/src/` contains exactly one file: `lib.rs`. The implementation had correctly placed `Selector` and `MacAddr` in a separate `src/selector.rs` module, but this violated the workspace structure test which enforces a single-file `src/lib.rs` layout for library crates.

The fix: copied all code from `selector.rs` (MacAddrParseError, MacAddr, Selector, and their tests) directly into `lib.rs`, merged the imports, removed the `mod selector;` and `pub use selector::...` declarations, and deleted `selector.rs`. No logic was changed.

## Remaining Issues
None.
