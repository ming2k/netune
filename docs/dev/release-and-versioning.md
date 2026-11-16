# Release & Versioning Process

This document defines how the `netune` workspace is versioned, tagged, and distributed. It is maintainer-facing: contributors do not need to run any of it.

---

## Principles: the repository owns the version

- **The tag is the release.** A release exists when an annotated tag matching the workspace version is pushed. The `Release` workflow then creates the GitHub Release from the matching `CHANGELOG.md` section. Nothing else defines a release.
- **We choose the numbers.** Version numbers follow this project's own line, not a registry's inventory. `netune-http2` was briefly carried at `0.0.2` only because the registry's `0.0.1` slot for that name was already taken; once distribution no longer depended on a registry, the whole workspace was flattened back to one lockstep version (section 1).
- **Distribution is by git** (section 3). No registry account, token, or upload participates in making a release, so a registry outage can neither block one nor invalidate one.
- **A yank is not a version decision.** Yanking withdraws a version from resolution; it does not free the number, and it does not delete content. Yanking every version of a crate makes that crate unresolvable for new consumers, so it is only ever done once a replacement version is available.

---

## 1. Versioning Model

Every crate is lockstep-versioned from a single source of truth:

| Location | Role |
| :--- | :--- |
| `Cargo.toml` → `[workspace.package] version` | The one version to bump |
| `crates/*/Cargo.toml` → `version.workspace = true` | Inherits it; never hard-code a literal |
| Internal `path` dependencies carrying a `version` | Must be re-pinned to the new number |

Version policy: starting at **`0.1.0` (GA)**, the **Stable** tier follows
pre-1.0 SemVer discipline:

- **Patch releases (`0.1.z`)** fix bugs, regressions, and security issues only
  without breaking Stable public APIs.
- **Minor releases (`0.y.0`)** introduce additive APIs and documented breaking or
  behavioral changes cleanly.
- **Preview & Experimental** crates remain opt-in and may still evolve between
  `0.x` releases when documented in `CHANGELOG.md`.

Prior `0.0.x` tags treated every patch as potentially breaking under Cargo's
initial `0.0.z` resolver semantics. Consumers should pin exact tags or use
`^0.1.0` once on GA.

---

## 2. Tag Convention

- Format: `vMAJOR.MINOR.PATCH` (e.g. `v0.1.0`), always an **annotated** (and SSH/GPG-signed where keys are configured) tag.
- Cut the tag on the release commit (the version-bump + `CHANGELOG.md` commit):

  ```bash
  git tag -s v0.1.0 -m "netune 0.1.0: GA release"
  git verify-tag v0.1.0
  git push origin main --follow-tags
  ```

- The CI `Release` workflow verifies the tag is a real annotated/signed tag object (`refs/tags/<tag>^{tag}`), verifies it matches `[workspace.package] version`, generates a CycloneDX SBOM asset (`cargo cyclonedx`), and creates the GitHub Release from `CHANGELOG.md`.
- Tags are immutable once pushed. A wrong tag is deleted and re-created on a corrected commit only before external consumption — nothing is published to a crate registry, so forward patch tags are preferred.

---

## 3. Distribution

Consumers depend on a tag:

```toml
netune = { git = "https://github.com/ming2k/netune", tag = "v0.1.1" }
```

- `tag` is the readable form, `rev = "<sha>"` the most reproducible. Never recommend `branch`.
- Cargo records the resolved commit in the consumer's `Cargo.lock`, so upgrades are explicit: change the tag and run `cargo update -p netune`.
- Trade-off accepted: no `cargo add` discoverability and no automatically built documentation site. Build docs locally with `cargo doc --workspace --all-features`, or from CI on request.

### Frozen registry state

The crates were published to crates.io once (`0.0.1` for five of them, `0.0.2` for `netune-http2`), and the superseded `0.1.x` line is yanked. Those artifacts are permanent and are **not** updated or maintained: this repository is the source of truth from here on. Reversing that decision means re-establishing a publication job and accepting the registry's existing version inventory as a starting point.

---

## 4. Release Checklist

1. `main` is green: CI (lockfile, tests, clippy, docs) passes.
2. Edit `[workspace.package] version` to the next version.
3. Re-pin every internal `path` dependency that carries a `version` to the new number.
4. Add a `CHANGELOG.md` entry following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) (`Added` / `Changed` / `Fixed`). The workflow reads this section, so it must exist before tagging.
5. Update the version tables in `README.md` (`Status`) and `docs/reference/crates.md`.
6. Verify locally:

   ```bash
   cargo check --all-targets --all-features
   cargo nextest run --workspace
   cargo clippy --all-targets --all-features -- -D warnings
   cargo fmt --check
   ```

7. Dry-run packaging and SemVer API checks before tagging:

   ```bash
   for manifest in crates/*/Cargo.toml; do
     name="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$manifest" | head -1)"
     grep -q '^publish *= *false' "$manifest" || cargo package --list --allow-dirty -p "$name" >/dev/null
   done
   ```

   For post-`0.1.0` releases, run `cargo semver-checks check-release --baseline-rev v0.1.0` on Stable crates to verify zero unintended breaking changes in patch/minor releases.

8. Commit as `netune X.Y.Z: <one-line summary>`, then create and push the annotated tag (section 2).
9. Watch the `Release` workflow: it creates the GitHub Release from the changelog. Spot-check the body.
10. If a consumer-facing snippet changed, confirm `README.md` shows the new tag.

---

## 5. Packaging Metadata

A crate directory does not inherit files from the workspace root, so the README is declared once and inherited, and the license is expressed as an SPDX identifier:

```toml
[workspace.package]
license = "MIT"
readme = "README.md"

# in each crates/*/Cargo.toml
license.workspace = true
readme.workspace = true
```

- `license` (SPDX) is what attribution tooling reads (`cargo-deny`, `cargo-about`). The license *text* travels with the git checkout at the repository root, and a git checkout is what distribution means for this project.
- Do **not** also set `license-file`: cargo warns `only one of \`license\` or \`license-file\` is necessary` on every build, for every manifest. Switch to `license-file` (instead of `license`) only if registry tarballs are shipped again, where a self-contained package needs the text embedded.
- `keywords` and `categories` are per-crate; `[package.metadata.docs.rs] all-features = true` documents the opt-in `netune-probe/inject` path.
- Confirm what a package would contain with `cargo package --list` (section 4, step 7).

---

## 6. Failure Handling

- There is no publication step, so the ordinary failure modes are CI red on `main` and a bad tag. Both are fixed forward: fix, commit, and re-tag only if the bad tag has not been consumed.
- If a consumer reports the release body is empty or malformed, check that `CHANGELOG.md` has a `## [X.Y.Z]` heading whose text equals the tag version (without the `v`).
- Do not force-push a tag that a consumer may already have pinned in a `Cargo.lock`; cut the next patch version instead.

---

## Links

- [ADR-0003](../adr/0003-workspace-decomposition-privilege-boundaries.md) — multi-crate decomposition and the requirement for workspace-wide version synchronization.
- [Contributor Environment & Test Setup](setup.md)
