# SPEC-502: RPM Packaging — Gap Analysis

## Current State

All primary packaging artifacts exist in the repository. The implementation is nearly complete but has one omission that will cause `rpmbuild` to fail with an "unpackaged files" error.

**`netfyr.spec`** (workspace root) — Two-package spec (`netfyr` and `netfyr-daemon`). Contains:
- Header: Name/Version/Release/License/URL/Source0/Source1, `ExclusiveArch: %{rust_arches}`
- BuildRequires: cargo/rust ≥ 1.86, rust-packaging ≥ 25, systemd-rpm-macros
- `%prep`: `%autosetup`, vendor tarball extraction, `%cargo_prep -v vendor`
- `%build`: `%cargo_build` + `cargo run -p xtask -- man` (correct, not the alias)
- `%install`: both binaries (`target/release/netfyr`, `target/release/netfyr-daemon`), man1/man5/man7 pages, systemd units from `dist/systemd/`, config dirs, example files
- `%check`: smoke-tests both binaries with `--help`
- Systemd scriptlets (`%systemd_post`, `%systemd_preun`, `%systemd_postun_with_restart`) scoped to `%package daemon`
- `%files` and `%files daemon` sections with `%license`, `%dir` directives
- `%changelog` entry

**`scripts/build-rpm.sh`** — exists, mode 755 (executable). Reads Name/Version from spec via `grep`/`awk`, creates `~/rpmbuild/` tree, generates git archive source tarball, runs `cargo vendor`, creates vendor tarball, removes `vendor/`, copies spec, runs `rpmbuild -ba`.

**`dist/systemd/netfyr.service`** — correct content: `Type=notify`, `ExecStart=/usr/bin/netfyr-daemon`, `RuntimeDirectory=netfyr`, `StateDirectory=netfyr`.

**`dist/systemd/netfyr.socket`** — correct content: `ListenStream=/run/netfyr/netfyr.sock`, `SocketMode=0666`.

**`man/`** — all eight man pages exist: `netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-history.1`, `netfyr-revert.1`, `netfyr.yaml.5`, `netfyr-examples.7`, **`netfyr-daemon.8`**.

**`examples/policies/bare-ethernet.yaml`** — exists.

**`LICENSE`** — exists at workspace root.

**`.gitignore`** — includes `/vendor`.

## Requirements

From the acceptance criteria:

1. `netfyr.spec` passes `rpmlint` with no errors and builds with `rpmbuild -ba`.
2. Two binary RPMs produced: `netfyr` and `netfyr-daemon`.
3. `netfyr` RPM owns: `/usr/bin/netfyr`, man1 pages, man5 page, man7 page, `/etc/netfyr/`, `/etc/netfyr/policies/`, example docs, LICENSE.
4. `netfyr-daemon` RPM owns: `/usr/bin/netfyr-daemon`, **man8 page**, systemd units, LICENSE.
5. `netfyr-daemon` declares `Requires: netfyr = %{version}-%{release}` and `Requires: systemd`.
6. Systemd units installed to `%{_unitdir}`.
7. `%license LICENSE` used (no manual LICENSE install).
8. Upgrade must not remove user config files under `/etc/netfyr/`.
9. `scripts/build-rpm.sh` is executable and reads Name/Version from spec.
10. `/vendor` remains gitignored and never committed.

## Gap Analysis

### Missing: man8 install in `%install` section (`netfyr.spec`)

The `%install` section installs man pages for sections 1, 5, and 7 but omits section 8. The file `man/netfyr-daemon.8` exists in the repository and will be present in the source tarball, but is never copied to the buildroot. `rpmbuild` will report it as an installed-but-unpackaged file.

**Required addition** after the man7 block (after line 58):

```specfile
install -d %{buildroot}%{_mandir}/man8
install -pm 0644 man/netfyr-daemon.8 %{buildroot}%{_mandir}/man8/
```

### Missing: man8 entry in `%files daemon` section (`netfyr.spec`)

The `%files daemon` section lists the daemon binary and systemd units but does not declare the man8 page. Without this entry `rpmbuild` will fail at the file list verification step.

**Required addition** after the `%{_bindir}/netfyr-daemon` line (after line 104):

```specfile
%{_mandir}/man8/netfyr-daemon.8*
```

### No other gaps

All other elements match the SPEC-502 requirements:
- Binary paths in `%install` and `%check` correctly use `target/release/netfyr` and `target/release/netfyr-daemon`.
- `%cargo_prep -v vendor` is present.
- `cargo run -p xtask -- man` is used (not the `cargo xtask` alias).
- `%license LICENSE` present in both `%files` sections; no manual LICENSE install.
- `%dir` directives for `/etc/netfyr` and `/etc/netfyr/policies/` present.
- `%changelog` entry present with correct date.
- Macro names in comments are escaped (`%%cargo_prep`, `%%cargo_install`).
- `build-rpm.sh` cleans up `vendor/` after tarball creation.
- `.gitignore` lists `/vendor`.
- Systemd units referenced as `dist/systemd/netfyr.service` and `dist/systemd/netfyr.socket`, matching actual file locations.

## Integration Points

- **`xtask/src/main.rs`**: Invoked in `%build` via `cargo run -p xtask -- man`. Must produce all man pages (including `netfyr-daemon.8`) into `man/` before `%install` runs.
- **`crates/netfyr-cli`**: Produces `target/release/netfyr` — already correctly referenced in `%install` and `%check`.
- **`crates/netfyr-daemon`**: Produces `target/release/netfyr-daemon` — already correctly referenced.
- **`dist/systemd/`**: Consumed by `%install`; paths in spec match actual filesystem layout.
- **`examples/policies/*.yaml`**: Shell glob in `%install`; currently one file. Glob will error if the directory is empty, but that is not currently the case.
- **`LICENSE`**: Required at workspace root for `%license` in both `%files` sections.

## Risks

1. **`rpmbuild` failure on unpackaged file**: Without the man8 additions, `rpmbuild -ba` will fail with `error: Installed (but unpackaged) file(s) found: /usr/share/man/man8/netfyr-daemon.8`. This is a build-blocking defect.

2. **`rpmlint` warnings for missing `Requires`**: The daemon binary links against `libsystemd` at runtime (via `sd-notify`). If not pulled in transitively by `systemd` itself, `rpmlint` may warn about missing shared-library `Requires`. The `Requires: systemd` declaration in `%package daemon` mitigates this for `libsystemd.so`.

3. **Man page regeneration in `%build`**: `cargo run -p xtask -- man` regenerates man pages that are also committed to the repo. The regenerated output may or may not be bit-identical. If xtask fails inside the RPM build environment (e.g., due to `%cargo_prep` overwriting `.cargo/config.toml`), the build halts. This is the documented rationale for using `-p xtask` instead of the alias.

4. **`SocketMode=0666`**: Allows any local user to submit policies to the daemon. A Fedora package review committee would require a tighter socket permission or polkit-based access control. Out of scope for this story but relevant if targeting official Fedora submission.

5. **Version drift**: `Version: 0.1.0` in the spec must stay synchronized with workspace `Cargo.toml`. No automated enforcement exists.

6. **Vendor tarball requires network**: `build-rpm.sh` calls `cargo vendor`, which fetches crates from the internet. Cannot run offline without a pre-populated registry cache.
