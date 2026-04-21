# Plan: SPEC-502 — RPM Packaging for Fedora

## Approach

The RPM packaging infrastructure is already implemented. Four files exist and are correct: `netfyr.spec`, `scripts/build-rpm.sh`, `dist/systemd/netfyr.service`, and `dist/systemd/netfyr.socket`. All supporting artifacts (man pages in `man/`, example policy in `examples/policies/`, `LICENSE` file, `.gitignore` with `/vendor`) are in place.

The only defect is that `netfyr.spec` does not install or declare the man8 page (`netfyr-daemon.8`) for the daemon subpackage. The `%install` section copies man pages for sections 1, 5, and 7, but omits section 8. The `%files daemon` section lists the daemon binary and systemd units but does not include the man8 entry. This means `rpmbuild -ba` will fail: `xtask` generates `man/netfyr-daemon.8` during `%build`, the file ends up in the build tree, but it is never installed into the buildroot and never declared as owned by any package. RPM will report an "installed but unpackaged file" error or (depending on build system configuration) silently omit it — either way violating the spec's FHS table which requires `/usr/share/man/man8/netfyr-daemon.8.gz` in the `netfyr-daemon` package.

The fix is two small additions to `netfyr.spec`: install commands in `%install` and a file declaration in `%files daemon`. No new files need to be created. No dependencies change. No other files require modification.

## Design Decisions

1. **Decision**: Add man8 installation commands to `%install` and a man8 file entry to `%files daemon` in the existing `netfyr.spec`.
   - **Alternatives considered**: (a) Skip the man8 page entirely and remove `man/netfyr-daemon.8` from the repo — rejected because the spec's FHS table explicitly requires the daemon man page in the daemon RPM, and omitting it would violate Fedora packaging guidelines for shipping binaries without man pages. (b) Ship the man8 page in the base `netfyr` package instead of `netfyr-daemon` — rejected because Fedora convention is to ship man pages with the binary they document, and `netfyr-daemon.8` documents the daemon binary which lives in the `netfyr-daemon` subpackage.
   - **Rationale**: The spec's FHS table explicitly places `netfyr-daemon.8` in the `netfyr-daemon` package. The man page already exists in the repo at `man/netfyr-daemon.8`. Adding the two missing blocks (install + files) is the minimal correct fix and follows the pattern already established by man sections 1, 5, and 7.

2. **Decision**: Place the man8 install commands immediately after the man7 block (after current line 58: `install -pm 0644 man/netfyr-examples.7 %{buildroot}%{_mandir}/man7/`), maintaining the ascending section-number order (man1 → man5 → man7 → man8).
   - **Alternatives considered**: Placing them in the systemd unit install block or at the end of `%install`.
   - **Rationale**: Grouping all man page installations together, in section order, matches the existing style and makes the spec easier to audit.

3. **Decision**: Place the `%{_mandir}/man8/netfyr-daemon.8*` entry in `%files daemon` immediately after `%{_bindir}/netfyr-daemon` (after current line 104), before the systemd unit entries.
   - **Alternatives considered**: Placing it after the systemd unit entries (lines 105-106).
   - **Rationale**: Mirrors the ordering convention in `%files` for the base package where man pages follow the binary entry. Groups "netfyr-daemon specific content" (binary + man page) before "infrastructure content" (systemd units).

4. **Decision**: Use the two-line `install -d` + `install -pm` pattern rather than `install -Dpm`.
   - **Alternatives considered**: Using `install -Dpm 0644 man/netfyr-daemon.8 %{buildroot}%{_mandir}/man8/netfyr-daemon.8` (single command that auto-creates parent directories).
   - **Rationale**: The existing man5 and man7 blocks use the two-line pattern (`install -d` to create the directory, then `install -pm` to copy the file). Consistency within the spec file matters more than saving one line.

## File Changes

### 1. `netfyr.spec` — modify

Two additions to the existing file:

**Addition A — `%install` section, after line 58 (after `install -pm 0644 man/netfyr-examples.7 %{buildroot}%{_mandir}/man7/`):**

Insert two lines to install the man8 page into the buildroot:
```
install -d %{buildroot}%{_mandir}/man8
install -pm 0644 man/netfyr-daemon.8 %{buildroot}%{_mandir}/man8/
```

- `install -d` creates the `man8` directory under the buildroot's mandir.
- `install -pm 0644` copies `man/netfyr-daemon.8` with correct permissions and preserves timestamps.
- This follows the exact same pattern as the man5 block (lines 55-56) and man7 block (lines 57-58).

**Addition B — `%files daemon` section, after line 104 (after `%{_bindir}/netfyr-daemon`):**

Insert one line declaring the man8 page as owned by the daemon subpackage:
```
%{_mandir}/man8/netfyr-daemon.8*
```

- The `*` glob suffix matches the `.gz` extension that `rpmbuild` adds when it compresses man pages during the build.
- This follows the same glob pattern used for all other man page entries in `%files` (e.g., `%{_mandir}/man1/netfyr.1*`).

**Why these changes are necessary**: Without Addition A, the man8 page is never copied from the source tree into the buildroot, so it cannot appear in any RPM. Without Addition B, even if the file were somehow present in the buildroot, RPM would not include it in the `netfyr-daemon` package (and would error on it as an unpackaged file). Both additions are required together.

### No other files need changes

All other artifacts have been verified as correct and complete:

- **`scripts/build-rpm.sh`** (mode 755): Creates source and vendor tarballs, reads Name/Version from spec, cleans up vendor/ after tarball creation, runs `rpmbuild -ba`. Correct as-is.
- **`dist/systemd/netfyr.service`**: `Type=notify`, `ExecStart=/usr/bin/netfyr-daemon`, `RuntimeDirectory=netfyr`, `StateDirectory=netfyr`, correct ordering targets. Matches spec.
- **`dist/systemd/netfyr.socket`**: `ListenStream=/run/netfyr/netfyr.sock`, `SocketMode=0666`. Matches spec.
- **`.gitignore`**: Contains `/vendor` (line 2). No change needed.
- **`man/`**: All eight man pages exist: `netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-history.1`, `netfyr-revert.1`, `netfyr.yaml.5`, `netfyr-examples.7`, `netfyr-daemon.8`.
- **`examples/policies/bare-ethernet.yaml`**: Present for the `%install` glob.
- **`LICENSE`**: Present at workspace root for `%license` directives in both `%files` sections.

## Dependencies

No new crate dependencies. This is a packaging metadata fix — no `Cargo.toml` files are modified.

## Implementation Order

1. **Edit `netfyr.spec`** — Apply both additions (A and B) described above. Both must be applied together in a single edit. After this step, the spec file is complete and consistent.

That is the entire implementation. One step, one file, two insertions.

## Risks and Mitigations

1. **Risk**: Incorrect insertion point causes the man8 install commands to appear inside a comment block or after an unrelated section.
   - **Mitigation**: The plan specifies exact line-level insertion points with surrounding context. The implementer should verify that the new lines appear (a) in `%install` between the man7 block and the systemd unit block, and (b) in `%files daemon` between the binary entry and the systemd unit entries.

2. **Risk**: `rpmlint` may flag informational warnings unrelated to this change (e.g., `non-standard-group`, socket permission warnings for `SocketMode=0666`).
   - **Mitigation**: The acceptance criteria states "no errors" from `rpmlint`. Informational warnings and notes are acceptable per Fedora packaging practice. The `%changelog` is already present (lines 108-110), which prevents the most common rpmlint error.

3. **Risk**: The `%build` step runs `cargo run -p xtask -- man` which regenerates man pages. If xtask's output has changed since the committed pages were generated, the installed content could differ from what's in the repo.
   - **Mitigation**: This is pre-existing behavior unrelated to this change. The regeneration ensures installed pages match the current code. If xtask output diverges, the build still succeeds — the `install` commands use whatever `cargo run -p xtask -- man` produces.

4. **Risk**: `%cargo_build` might not build the daemon binary if the workspace has `default-members` restrictions.
   - **Mitigation**: The workspace `Cargo.toml` has no `default-members` restriction (verified from codebase context), so `%cargo_build` builds all workspace members including both `netfyr-cli` and `netfyr-daemon` crates.

5. **Risk**: Version drift between `Version: 0.1.0` in the spec and individual `Cargo.toml` versions.
   - **Mitigation**: Out of scope for this story. Both are currently `0.1.0`. No automated sync exists, but this is a known accepted risk noted in the understanding analysis.

## Test Strategy

Since this is a packaging metadata fix (not Rust code), validation is through packaging tools, not Rust test harnesses:

1. **Visual inspection**: Verify the `%install` section now has install commands for man sections 1, 5, 7, and 8 in ascending order. Verify `%files daemon` now includes `%{_mandir}/man8/netfyr-daemon.8*` between the binary and systemd unit entries.

2. **Grep verification**: Confirm `man8` appears in both the `%install` and `%files daemon` sections of `netfyr.spec`. A quick `grep -n man8 netfyr.spec` should show exactly 3 lines (the `install -d`, the `install -pm`, and the `%files` entry).

3. **rpmlint**: Run `rpmlint netfyr.spec` and confirm no errors related to file lists or man pages.

4. **Spec parse check**: If `rpmspec` is available, run `rpmspec -P netfyr.spec` to verify macro expansion produces correct `install` commands for all four man page sections.

5. **Full RPM build** (if `rpmbuild` and Rust toolchain available): Run `./scripts/build-rpm.sh` end-to-end. Verify:
   - Build exits 0 with no "unpackaged files" errors
   - `rpm -qlp` on the `netfyr-daemon` RPM shows `/usr/share/man/man8/netfyr-daemon.8.gz`
   - `rpm -qlp` on the `netfyr` RPM still shows all man1, man5, man7 pages (regression check)
   - Both RPMs install cleanly with `dnf install`

6. **File list completeness**: Compare `rpm -qlp` output for both RPMs against the FHS table in SPEC-502 to confirm every expected path is present and assigned to the correct package.

No Rust test code needs to be written. The acceptance criteria scenarios from the spec serve as the test plan — they are validated through the RPM build system.
