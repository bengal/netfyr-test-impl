# Plan: SPEC-502 — RPM Packaging for Fedora

## Approach

This story creates the RPM packaging infrastructure for netfyr: a spec file, a build helper script, and supporting files (LICENSE, example policies, .gitignore update). No Rust code is modified — this is purely a packaging task producing four new files and two small edits.

The spec file produces two binary RPMs (`netfyr` and `netfyr-daemon`) from a single source RPM, following Fedora's `rust-packaging` conventions. The build uses vendored dependencies (offline mode via `%cargo_prep -v vendor`) so it works in isolated build environments like Koji/mock. The daemon subpackage depends on the CLI package and includes systemd integration via standard RPM macros.

The alternative approach — a single monolithic RPM containing both binaries — was rejected because the daemon is optional (only needed for DHCP/dynamic factories) and pulls in a systemd dependency that pure-CLI users don't need. Splitting into two packages follows the established pattern for daemon+CLI tools in Fedora (e.g., `podman` / `podman-remote`).

## Design Decisions

1. **Decision**: Reference the actual systemd unit paths (`dist/systemd/netfyr.service` and `dist/systemd/netfyr.socket`) in the spec file, rather than moving the files to `dist/`.
   - **Alternatives considered**: Moving the files to `dist/` flat to match the spec template exactly.
   - **Rationale**: The files already exist at `dist/systemd/`. Moving them would break any other references and is unnecessary churn — adjusting two paths in the spec is simpler and preserves the existing directory organization.

2. **Decision**: Install `target/release/netfyr-cli` as `/usr/bin/netfyr` (renaming during install).
   - **Alternatives considered**: Renaming the `[[bin]]` in `crates/netfyr-cli/Cargo.toml` from `netfyr-cli` to `netfyr`.
   - **Rationale**: The binary is defined as `netfyr-cli` in `Cargo.toml` (`[[bin]] name = "netfyr-cli"`). Changing the Cargo binary name would affect the entire build system and is outside the scope of this packaging story. The `install` command trivially renames during installation, which is standard RPM practice. The `%check` section must also reference `target/release/netfyr-cli`.

3. **Decision**: Add a `%changelog` section to the spec file.
   - **Alternatives considered**: Omitting it (as the spec template does).
   - **Rationale**: `rpmlint` reports an error for missing `%changelog`, and Fedora packaging guidelines require it. Adding a single initial entry satisfies both requirements.

4. **Decision**: Use MIT license text for the `LICENSE` file.
   - **Alternatives considered**: None — the spec declares `License: MIT`.
   - **Rationale**: The `%license LICENSE` directive in both `%files` sections requires this file to exist. The spec explicitly declares `License: MIT`.

5. **Decision**: Create a minimal but realistic `examples/policies/bare-ethernet.yaml` example file.
   - **Alternatives considered**: Creating multiple example files, or a trivial placeholder.
   - **Rationale**: The spec's `%install` section globs `examples/policies/*.yaml`. At least one file must exist or the shell glob fails. A realistic example serves double duty: it prevents the build failure and provides actual user value. The spec's `rpm -ql` output shows `bare-ethernet.yaml` specifically, so that's the filename to use.

6. **Decision**: Escape macro names in spec comments using `%%` (double-percent).
   - **Alternatives considered**: Avoiding comments that mention macros.
   - **Rationale**: RPM expands macros even inside comments. The spec template's note about `%cargo_install` in a comment would cause a parse error. All macro references in comments must be doubled.

7. **Decision**: The vendor tarball is created on-the-fly by the build script and never committed.
   - **Alternatives considered**: Checking in a pre-built vendor tarball.
   - **Rationale**: The vendored dependencies are hundreds of megabytes. The build script runs `cargo vendor` to create the tarball fresh each time. Adding `/vendor` to `.gitignore` prevents accidental commits.

## File Changes

### 1. `netfyr.spec` (create)

RPM spec file at the workspace root. Contains:

- **Preamble**: `Name: netfyr`, `Version: 0.1.0`, `Release: 1%{?dist}`, `Summary`, `License: MIT`, `URL`, `Source0` (source tarball), `Source1` (vendor tarball), `ExclusiveArch: %{rust_arches}`, `BuildRequires` for `cargo >= 1.86`, `rust >= 1.86`, `rust-packaging >= 25`, `systemd-rpm-macros`.
- **`%description`**: Multi-line description of netfyr.
- **`%package daemon`**: Subpackage with `Summary`, `Requires: %{name} = %{version}-%{release}`, `Requires: systemd`.
- **`%description daemon`**: Description of the daemon subpackage.
- **`%prep`**: `%autosetup -n %{name}-%{version}`, extract `%{SOURCE1}` (vendor tarball), call `%cargo_prep -v vendor`.
- **`%build`**: `%cargo_build`, then `cargo run -p xtask -- man` (NOT `cargo xtask man` — the `.cargo/config.toml` alias may not exist after `%cargo_prep`).
- **`%install`**:
  - Install `target/release/netfyr-cli` as `%{buildroot}%{_bindir}/netfyr` (mode 0755). Note the rename from `netfyr-cli` to `netfyr`.
  - Install `target/release/netfyr-daemon` as `%{buildroot}%{_bindir}/netfyr-daemon` (mode 0755).
  - Install man pages from `man/` into appropriate `%{_mandir}` subdirectories (man1, man5, man7).
  - Install systemd units from `dist/systemd/netfyr.service` and `dist/systemd/netfyr.socket` to `%{_unitdir}`.
  - Create `%{buildroot}%{_sysconfdir}/netfyr/policies` directory.
  - Install example policy files from `examples/policies/*.yaml` to `%{_docdir}/%{name}/examples/policies/`.
  - Do NOT manually install LICENSE (handled by `%license`).
- **`%check`**: Smoke-test both binaries: `target/release/netfyr-cli --help > /dev/null` and `target/release/netfyr-daemon --help > /dev/null`. Note: must use `netfyr-cli` (the actual binary name), not `netfyr`.
- **`%post daemon`** / **`%preun daemon`** / **`%postun daemon`**: systemd scriptlets using `%systemd_post`, `%systemd_preun`, `%systemd_postun_with_restart` for `netfyr.service netfyr.socket`.
- **`%files`**: `%license LICENSE`, `%{_bindir}/netfyr`, man pages (with glob `*` suffix for compression), `%dir %{_sysconfdir}/netfyr`, `%dir %{_sysconfdir}/netfyr/policies`, `%{_docdir}/%{name}/examples/policies/`.
- **`%files daemon`**: `%license LICENSE`, `%{_bindir}/netfyr-daemon`, both systemd unit files.
- **`%changelog`**: One initial entry dated today (Wed Apr 15 2026 or the appropriate day-of-week for the release), with a brief "Initial package" message. Use a placeholder maintainer name/email.

**Why**: This is the core deliverable — the spec file that drives `rpmbuild` to produce installable RPMs.

### 2. `scripts/build-rpm.sh` (create)

Shell script (mode 0755) that automates the RPM build. Contains:

- Shebang `#!/bin/bash` and `set -euo pipefail`.
- Derive `SCRIPT_DIR` and `REPO_ROOT` from `$0`.
- Extract `NAME` and `VERSION` from `netfyr.spec` using `grep` + `awk`.
- Create `~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}` directory tree.
- Create source tarball via `git archive --format=tar.gz --prefix=${NAME}-${VERSION}/ -o ~/rpmbuild/SOURCES/${NAME}-${VERSION}.tar.gz HEAD`.
- Create vendor tarball: run `cargo vendor vendor`, then `tar czf ~/rpmbuild/SOURCES/${NAME}-${VERSION}-vendor.tar.gz vendor/`, then `rm -rf vendor/` (clean up after ourselves).
- Copy `netfyr.spec` to `~/rpmbuild/SPECS/`.
- Run `rpmbuild -ba ~/rpmbuild/SPECS/netfyr.spec`.
- Print paths of resulting RPMs using `find`.

**Why**: Provides a one-command workflow for developers to build RPMs locally. Extracts metadata from the spec to keep version numbers in sync.

### 3. `LICENSE` (create)

Standard MIT license text file at the workspace root. Use the year 2024 (or current year) and "The netfyr authors" as the copyright holder. The full MIT license body follows the SPDX-standard template.

**Why**: Required by the `%license LICENSE` directive in both `%files` sections. Without this file, `rpmbuild` fails during the `%install` phase.

### 4. `examples/policies/bare-ethernet.yaml` (create)

A minimal but realistic YAML policy file demonstrating basic Ethernet configuration. Should define a single policy with a static factory that configures an Ethernet interface. The content should match the netfyr policy format as used by `netfyr-policy`'s YAML parser — specifically, a document with `name`, `factory` (type: `static`), and `states` fields containing an `ethernet` entity type with a selector and fields like `mtu`.

Example structure (the implementer should use the actual policy format as parsed by `parse_policy_yaml`):
```yaml
name: bare-ethernet
factory:
  type: static
states:
  - type: ethernet
    selector:
      name: eth0
    fields:
      mtu: 1500
```

The implementer should verify the exact field names by reading `crates/netfyr-policy/src/lib.rs` to ensure the example parses correctly.

**Why**: The spec's `%install` section runs `install -pm 0644 examples/policies/*.yaml` which will fail if no YAML files exist in that directory.

### 5. `.gitignore` (modify)

Append `/vendor` on a new line to the existing `.gitignore` (which currently only contains `/target`).

**Why**: Prevents accidental commits of the vendored dependency directory (hundreds of megabytes, thousands of files) that `cargo vendor` creates during the build script.

### 6. `examples/policies/` directory (create)

Create the `examples/policies/` directory (implied by creating the YAML file above, but noting it explicitly since the directory doesn't exist).

**Why**: Required for the `%install` glob and the `%files` doc directive.

## Dependencies

No new crate dependencies. This story only creates packaging artifacts (spec file, shell script, license, example files). All existing Cargo.toml files remain unchanged.

## Implementation Order

1. **Create `LICENSE`** — No dependencies. Required before the spec file can be tested. Create the MIT license file at the workspace root.

2. **Create `examples/policies/bare-ethernet.yaml`** — No dependencies on other steps. Create the directory and example file. The implementer should briefly read `crates/netfyr-policy/src/lib.rs` to verify the policy YAML format.

3. **Update `.gitignore`** — No dependencies. Append `/vendor` line.

4. **Create `netfyr.spec`** — Depends on steps 1-3 (the files referenced in the spec must exist). This is the main deliverable. The implementer must account for:
   - Binary name `netfyr-cli` (not `netfyr`) in install and check sections.
   - Systemd unit path `dist/systemd/` (not `dist/`).
   - Escaped macro names in comments (`%%cargo_prep`, etc.).
   - `%changelog` section at the end.

5. **Create `scripts/build-rpm.sh`** — Depends on step 4 (reads the spec file). Create the script and ensure it has the executable bit set (`chmod +x`).

Each step produces a valid, committable state. Steps 1-3 are independent and can be done in any order or in parallel. Step 4 depends on 1-3 existing. Step 5 depends on 4.

## Risks and Mitigations

1. **CLI binary name mismatch** (`netfyr-cli` vs `netfyr`)
   - **Risk**: The spec template in the story says `target/release/netfyr`, but the actual Cargo binary is `netfyr-cli` (per `crates/netfyr-cli/Cargo.toml` `[[bin]] name = "netfyr-cli"`). Using the wrong name causes `%install` to fail with "No such file or directory".
   - **Mitigation**: The spec must reference `target/release/netfyr-cli` in the `install` command and `%check` section, while still installing it as `netfyr` at `/usr/bin/netfyr`. The `install -Dpm 0755 target/release/netfyr-cli %{buildroot}%{_bindir}/netfyr` command handles the rename.

2. **Systemd unit path mismatch** (`dist/` vs `dist/systemd/`)
   - **Risk**: The spec template references `dist/netfyr.service` and `dist/netfyr.socket`, but the actual files are at `dist/systemd/netfyr.service` and `dist/systemd/netfyr.socket`.
   - **Mitigation**: Use the actual paths (`dist/systemd/`) in the spec's `%install` section.

3. **Missing prerequisite man pages**
   - **Risk**: This story depends on SPEC-501 and SPEC-503 which produce the hand-maintained man pages (`man/netfyr.yaml.5` and `man/netfyr-examples.7`). The xtask generates the section-1 pages during `%build`, but the section-5 and section-7 pages must already exist in the source tarball. If the prerequisite stories have not been implemented, `%install` will fail when trying to install these files.
   - **Mitigation**: The plan assumes prerequisites are met. If the man pages don't exist at build time, the `install` commands for those specific files will fail clearly, pointing to the missing dependency. The implementer should verify these files exist before testing the RPM build.

4. **`%cargo_prep` overwrites `.cargo/config.toml`**
   - **Risk**: The `%cargo_prep` macro may overwrite or remove `.cargo/config.toml`, which contains the `cargo xtask` alias.
   - **Mitigation**: The spec uses `cargo run -p xtask -- man` (direct invocation) instead of `cargo xtask man` (alias-based). This is explicitly called out in the spec story.

5. **`rpmlint` failures**
   - **Risk**: Missing `%changelog` will cause rpmlint errors. Macro expansion in comments will cause parse failures.
   - **Mitigation**: Include a `%changelog` section. Double all `%` signs in comments that reference macro names (e.g., `%%cargo_install`).

6. **Vendor directory accidentally committed**
   - **Risk**: Running the build script creates a `vendor/` directory before creating the tarball. If the developer interrupts the script or it fails after `cargo vendor` but before cleanup, `vendor/` will remain on disk. Without `.gitignore` protection, it could be committed.
   - **Mitigation**: Add `/vendor` to `.gitignore` (step 3). The build script should also clean up `vendor/` after creating the tarball (add `rm -rf vendor/` after `tar czf`).

7. **Example policy file format**
   - **Risk**: If the example YAML doesn't match the actual policy parser format, it won't be usable as documentation and could mislead users.
   - **Mitigation**: The implementer should read `crates/netfyr-policy/src/lib.rs` (specifically `parse_policy_from_value` and the `Policy` struct) to verify the correct YAML structure before writing the example.

8. **`%cargo_build` macro behavior**
   - **Risk**: The `%cargo_build` macro from `rust-packaging` may pass different flags than a plain `cargo build --release`. It may not build all workspace members by default, or may build only the default members.
   - **Mitigation**: Verify that `%cargo_build` builds the full workspace. If it only builds the default package, the spec may need to pass `--workspace` or explicitly name the packages. The Cargo workspace has no `default-members`, so `%cargo_build` should build all members.

## Test Strategy

This story is primarily packaging infrastructure, so testing focuses on build validation rather than unit tests. No Rust test code is needed.

**Build validation tests** (manual or CI):
- Run `rpmlint netfyr.spec` — should report no errors (warnings about missing source tarballs are acceptable for a standalone lint check).
- Run `./scripts/build-rpm.sh` on a Fedora system with `rust-packaging` installed — should exit 0 and produce RPMs.
- Install both RPMs and verify `rpm -ql netfyr` and `rpm -ql netfyr-daemon` match the expected file lists.
- Verify `netfyr --help` and `netfyr-daemon --help` work after installation.
- Verify `man netfyr` displays the man page.
- Verify `systemctl cat netfyr.service` and `systemctl cat netfyr.socket` display correct unit files.
- Verify `rpm -qR netfyr-daemon` lists `netfyr` and `systemd` as dependencies.

**File existence tests** (can be checked statically):
- `netfyr.spec` exists at workspace root.
- `scripts/build-rpm.sh` exists and is executable.
- `LICENSE` exists at workspace root.
- `examples/policies/bare-ethernet.yaml` exists and is valid YAML.
- `.gitignore` contains `/vendor`.

**Spec file content tests** (can be checked with grep/assertions):
- Spec references `netfyr-cli` (not `netfyr`) for the CLI binary path in `%install` and `%check`.
- Spec references `dist/systemd/` (not `dist/`) for systemd unit paths.
- Spec contains `%changelog` section.
- Spec contains `%license LICENSE` in both `%files` and `%files daemon`.
- No unescaped macro names in comments.
