# Plan: SPEC-502 — RPM Packaging for Fedora

## Approach

The RPM packaging infrastructure is already implemented. Four files exist: `netfyr.spec`, `scripts/build-rpm.sh`, `dist/systemd/netfyr.service`, and `dist/systemd/netfyr.socket`. All supporting artifacts (man pages in `man/`, example policy in `examples/policies/`, `LICENSE` file, `.gitignore` with `/vendor`) are in place.

The only required change is a **bug fix in `netfyr.spec`**: lines 47 and 77 reference `target/release/netfyr-cli`, but the correct CLI binary is `target/release/netfyr`. The `netfyr-cli` crate declares two `[[bin]]` targets in its `Cargo.toml`: `name = "netfyr"` (from `src/main.rs`, the primary CLI) and `name = "netfyr-cli"` (from `src/netfyr_cli_main.rs`, a secondary entry point). Cargo outputs both as separate binaries. The spec needs to reference the primary one — `target/release/netfyr` — which is the binary that should be installed as `/usr/bin/netfyr`.

No new files need to be created. No dependencies change. No Rust code is modified. The fix is two path corrections and cleanup of two misleading comments.

The alternative of renaming the Cargo `[[bin]]` entry was rejected because it would be a cross-cutting change affecting other stories, test infrastructure, and the crate's public build artifacts. Fixing the spec to reference the correct existing binary name is the minimal, correct solution.

## Design Decisions

1. **Decision**: Change `target/release/netfyr-cli` to `target/release/netfyr` in the spec's `%install` and `%check` sections.
   - **Alternatives considered**: (a) Renaming the `[[bin]]` in `crates/netfyr-cli/Cargo.toml` to only produce `netfyr-cli` and keeping the spec's rename approach. (b) Keeping the spec as-is (which would fail at build time).
   - **Rationale**: The Cargo workspace already produces `target/release/netfyr` as the primary CLI binary. The spec should reference this directly. The current spec references the secondary binary (`netfyr-cli`) which is not intended for installation. Installing `target/release/netfyr` to `%{_bindir}/netfyr` is a no-rename copy — simple and correct.

2. **Decision**: Remove the misleading comment on line 46 that says "the Cargo binary is named netfyr-cli; rename on install".
   - **Alternatives considered**: Updating the comment to say "the Cargo binary is named netfyr".
   - **Rationale**: The install command `install -Dpm 0755 target/release/netfyr %{buildroot}%{_bindir}/netfyr` is self-explanatory. A simpler comment ("Install CLI binary") matches the style used for the daemon binary on line 49.

3. **Decision**: Remove the misleading comment on line 76 that says "the CLI binary is named netfyr-cli in the build output".
   - **Alternatives considered**: Keeping a corrected comment.
   - **Rationale**: The smoke-test command `target/release/netfyr --help > /dev/null` is self-evident. The existing comment above it on line 75 ("Smoke-test: verify the built binaries are functional.") provides sufficient context.

## File Changes

### 1. `netfyr.spec` — modify

Four changes, all in the same file:

**Change A — Line 46 (comment fix):**
- **Current**: `# Install CLI binary (the Cargo binary is named netfyr-cli; rename on install)`
- **New**: `# Install CLI binary`
- **Why**: The comment is factually wrong — the binary is named `netfyr`, not `netfyr-cli`.

**Change B — Line 47 (binary path fix in `%install`):**
- **Current**: `install -Dpm 0755 target/release/netfyr-cli %{buildroot}%{_bindir}/netfyr`
- **New**: `install -Dpm 0755 target/release/netfyr %{buildroot}%{_bindir}/netfyr`
- **Why**: The primary CLI binary produced by Cargo is `target/release/netfyr`. The current path `target/release/netfyr-cli` references the secondary entry point, causing `%install` to fail with "No such file or directory" (or worse, install the wrong binary if both exist).

**Change C — Line 76 (comment removal in `%check`):**
- **Current**: `# Note: the CLI binary is named netfyr-cli in the build output.`
- **Remove this line entirely.**
- **Why**: Factually wrong and misleading. The preceding comment on line 75 is sufficient.

**Change D — Line 77 (binary path fix in `%check`):**
- **Current**: `target/release/netfyr-cli --help > /dev/null`
- **New**: `target/release/netfyr --help > /dev/null`
- **Why**: Must smoke-test the same binary that gets installed. The current line tests the wrong binary.

### No other files need changes

All other files are already correct and require no modifications:

- **`scripts/build-rpm.sh`**: Executable (mode 755 confirmed), reads Name/Version from spec, creates source and vendor tarballs, cleans up vendor/ after tarball creation, copies spec to `~/rpmbuild/SPECS/`, runs `rpmbuild -ba`. Matches spec requirements exactly.
- **`dist/systemd/netfyr.service`**: `Type=notify`, `ExecStart=/usr/bin/netfyr-daemon`, `RuntimeDirectory=netfyr`, `StateDirectory=netfyr`, correct ordering targets (`After=network-pre.target`, `Before=network.target`). Matches spec.
- **`dist/systemd/netfyr.socket`**: `ListenStream=/run/netfyr/netfyr.sock`, `SocketMode=0666`. Matches spec.
- **`.gitignore`**: Already contains `/vendor` (along with `/target` and `/.factory/`).
- **`man/`**: All seven man pages exist: `netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-history.1`, `netfyr-revert.1`, `netfyr.yaml.5`, `netfyr-examples.7`.
- **`examples/policies/bare-ethernet.yaml`**: Exists for the `%install` glob.
- **`LICENSE`**: Exists at workspace root for `%license` directive.

## Dependencies

No new crate dependencies. This is a packaging-only change — no `Cargo.toml` files are modified.

## Implementation Order

1. **Fix `netfyr.spec`** — Apply all four changes (A through D) described above. This is a single atomic edit to one file. The spec parses correctly before and after — there is no intermediate broken state.

That is the entire implementation. One step, one file, four edits.

## Risks and Mitigations

1. **Risk**: The secondary binary `target/release/netfyr-cli` (from `src/netfyr_cli_main.rs`) is also built by `%cargo_build` but is not installed. If it serves a purpose that requires packaging, it would be missing.
   - **Mitigation**: The spec explicitly requires only `/usr/bin/netfyr` and `/usr/bin/netfyr-daemon`. The `netfyr-cli` binary is a secondary entry point not called for in the packaging requirements. If it needs packaging in the future, a third `install` line can be added.

2. **Risk**: `rpmlint` may flag warnings unrelated to this change (e.g., `non-standard-group`, socket permission warnings for `SocketMode=0666`, or informational notes).
   - **Mitigation**: The acceptance criteria says "no errors" from rpmlint. Informational warnings and notes are acceptable. The `%changelog` is already present (lines 109-111), which prevents the most common rpmlint error.

3. **Risk**: The `%build` step runs `cargo run -p xtask -- man` to regenerate man pages. If the xtask binary has changed since the committed man pages were generated, the output could differ.
   - **Mitigation**: The man pages are committed to the repo and regeneration is a consistency check. If xtask output diverges, the build still succeeds (the `install` commands use the generated output). The regeneration ensures the installed pages match the current code.

4. **Risk**: `%cargo_build` might not build all workspace members, leaving `target/release/netfyr` or `target/release/netfyr-daemon` missing.
   - **Mitigation**: The Cargo workspace has no `default-members` restriction, so `%cargo_build` (which wraps `cargo build --release`) builds all members. Both binaries will be produced.

5. **Risk**: Version drift between `Version: 0.1.0` in the spec and `version = "0.1.0"` in individual `Cargo.toml` files.
   - **Mitigation**: Out of scope for this story. The version is 0.1.0 in both places currently. An automated version-sync check could be added later.

## Test Strategy

Since this is a packaging fix (not Rust code), traditional unit/integration tests don't apply. Validation focuses on:

1. **Spec correctness**: Verify that `netfyr.spec` lines 47 and 77 now reference `target/release/netfyr` (not `netfyr-cli`). This can be checked with a simple grep.

2. **Binary name verification**: Run `cargo build --release -p netfyr-cli` and confirm `target/release/netfyr` exists. This validates that the spec references a binary that actually gets built.

3. **Spec parse check**: If `rpmspec` is available, run `rpmspec -P netfyr.spec` to verify macro expansion produces the correct `install` commands.

4. **rpmlint**: Run `rpmlint netfyr.spec` to verify no errors.

5. **Full RPM build** (if rpmbuild is available in the environment): Run `./scripts/build-rpm.sh` end-to-end. Verify:
   - Build exits 0
   - `netfyr-0.1.0-1.*.rpm` and `netfyr-daemon-0.1.0-1.*.rpm` are produced
   - `rpm -qlp` on both RPMs shows expected file lists

6. **Post-install smoke tests** (if in a Fedora environment with dnf):
   - `netfyr --help` exits 0
   - `netfyr-daemon --help` exits 0
   - `man netfyr` renders
   - `systemctl cat netfyr.service` shows correct content
   - `rpm -qR netfyr-daemon` lists `netfyr` and `systemd`

No Rust test code needs to be written. The acceptance criteria scenarios from the spec serve as the complete test plan — they are validated through the RPM build system, not through Rust test harnesses.
