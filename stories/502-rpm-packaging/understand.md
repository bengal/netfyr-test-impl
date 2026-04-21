# SPEC-502: RPM Packaging — Gap Analysis

## Current State

All required packaging artifacts already exist in the repository. The implementation is largely complete but contains one build-breaking correctness bug.

**`netfyr.spec`** — exists at `/workspace/netfyr.spec`. Two-package spec (`netfyr` and `netfyr-daemon`) using `%cargo_prep -v vendor` / `%cargo_build`, systemd scriptlets, `%check` section, and `%changelog`. The `dist/systemd/` path for systemd units is already correct in the spec. Contains one critical bug (see Gap Analysis).

**`scripts/build-rpm.sh`** — exists at `/workspace/scripts/build-rpm.sh`. Reads `Name` and `Version` from the spec via `grep`/`awk`, creates source and vendor tarballs, cleans up `vendor/` after tarball creation, copies spec to `~/rpmbuild/SPECS/`, runs `rpmbuild -ba`.

**`dist/systemd/netfyr.service`** — exists. Content matches spec: `Type=notify`, `ExecStart=/usr/bin/netfyr-daemon`, `RuntimeDirectory=netfyr`, `StateDirectory=netfyr`, `After=network-pre.target`.

**`dist/systemd/netfyr.socket`** — exists. Content matches spec: `ListenStream=/run/netfyr/netfyr.sock`, `SocketMode=0666`.

**Man pages** — all seven expected pages exist under `man/`: `netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-history.1`, `netfyr-revert.1`, `netfyr.yaml.5`, `netfyr-examples.7`.

**`examples/policies/bare-ethernet.yaml`** — exists.

**`LICENSE`** — exists at workspace root.

**`.gitignore`** — includes `/vendor`, preventing accidental commits of the vendored dependency tree.

**Binaries**: `crates/netfyr-cli/Cargo.toml` declares two binaries:
- `name = "netfyr"` from `src/main.rs` → produces `target/release/netfyr` (the installable CLI)
- `name = "netfyr-cli"` from `src/netfyr_cli_main.rs` → produces `target/release/netfyr-cli` (secondary entry point)

`crates/netfyr-daemon/Cargo.toml` declares one binary: `name = "netfyr-daemon"` → produces `target/release/netfyr-daemon`.

## Requirements

The spec requires:

1. `netfyr.spec` at workspace root, valid per `rpmlint`, producing two sub-packages.
2. `%install` installs `target/release/netfyr` (not `netfyr-cli`) as `/usr/bin/netfyr`.
3. `%check` smoke-tests `target/release/netfyr --help` (not `netfyr-cli --help`).
4. `scripts/build-rpm.sh` is executable, reads `Name`/`Version` from spec, creates tarballs.
5. Systemd units installed from `dist/systemd/`.
6. Man pages installed from `man/` into correct sections.
7. `examples/policies/*.yaml` installed into `%{_docdir}/netfyr/examples/policies/`.
8. `%dir` ownership for `/etc/netfyr` and `/etc/netfyr/policies/`.
9. `%license LICENSE` in both `%files` sections (no manual `install` of LICENSE).
10. Systemd scriptlets (`%systemd_post`, `%systemd_preun`, `%systemd_postun_with_restart`) scoped to `%package daemon`.

## Gap Analysis

### Critical bug — wrong binary name referenced in `netfyr.spec`

`netfyr.spec` lines 47 and 77 reference `target/release/netfyr-cli`:

```
# line 47 (%install)
install -Dpm 0755 target/release/netfyr-cli %{buildroot}%{_bindir}/netfyr

# line 77 (%check)
target/release/netfyr-cli --help > /dev/null
```

The primary CLI binary produced by the `netfyr-cli` crate is `target/release/netfyr` (declared as `name = "netfyr"` in `Cargo.toml`). The `netfyr-cli` binary is a separate secondary entry point. The spec's `%install` step will fail with "file not found" unless corrected.

**Required fix in `netfyr.spec`:**
- Line 47: `target/release/netfyr-cli` → `target/release/netfyr`; remove the misleading comment "(the Cargo binary is named netfyr-cli; rename on install)"
- Line 77: `target/release/netfyr-cli` → `target/release/netfyr`

No other files need modification.

### `scripts/build-rpm.sh` executable bit

The script must have the executable bit set (`chmod +x`). This cannot be verified from static analysis — it must be confirmed in the working tree.

### No other gaps

All other elements match the SPEC-502 requirements:
- `%cargo_prep -v vendor` is present in `%prep`.
- `cargo run -p xtask -- man` is used (not the `cargo xtask` alias).
- LICENSE is handled only via `%license LICENSE` — no double-installation.
- `%check` is present.
- Systemd scriptlets are present and scoped to `%package daemon`.
- `%dir` directives for `/etc/netfyr` and `/etc/netfyr/policies/` are present.
- `%changelog` entry is present.
- Macro names in spec comments are escaped (`%%cargo_prep`, `%%cargo_install`).
- `build-rpm.sh` cleans up `vendor/` after tarball creation (`rm -rf vendor/`).
- `.gitignore` lists `/vendor`.

## Integration Points

- **`xtask/src/main.rs`**: Invoked in `%build` via `cargo run -p xtask -- man`. Generates section-1 man pages from clap definitions into `man/`. Must support the `man` subcommand.
- **`crates/netfyr-cli`**: Produces `target/release/netfyr` — the path the spec must reference in `%install` and `%check`.
- **`crates/netfyr-daemon`**: Produces `target/release/netfyr-daemon` — already correct in the spec.
- **`dist/systemd/netfyr.service` and `dist/systemd/netfyr.socket`**: Consumed by `%install` at lines 61–62 of the spec. Paths are already consistent with the actual file locations.
- **`examples/policies/*.yaml`**: Shell glob in `%install`; currently one file exists. Glob will error if the directory is empty.
- **`LICENSE`**: Required at workspace root for `%license LICENSE` in both `%files` sections.

## Risks

1. **Build-breaking binary name bug**: The `%install` and `%check` sections reference `target/release/netfyr-cli`, which is not the installed binary. An `rpmbuild -ba` run will fail at `%install` unless this is corrected.

2. **`rpmlint` validation not yet run**: Despite the `%changelog` being present, `rpmlint` may still flag issues such as missing `BuildRequires` for C libraries pulled in by transitive crates (`rtnetlink`, `socket2`, `libc`-based crates can require `gcc` or system headers).

3. **`cargo run -p xtask -- man` in RPM build environment**: The `%build` step regenerates man pages. If the xtask `man` subcommand fails or produces different output than what is tracked in `man/`, the build will either fail or install stale pages. The man pages are committed to the repo; the regeneration step could be a no-op or could diverge.

4. **Workspace version drift**: `Version: 0.1.0` in the spec must stay synchronized with `version = "0.1.0"` in individual `Cargo.toml` files. There is no automated enforcement.

5. **`SocketMode=0666` on the Varlink socket**: Allows any local user to connect to the daemon. A Fedora package review would flag this as a security concern — out of scope for this story but relevant if targeting official Fedora submission.

6. **Vendor tarball requires network access**: `cargo vendor` in `build-rpm.sh` fetches crates from the internet. The script cannot be run in an air-gapped environment without a pre-populated registry cache.
