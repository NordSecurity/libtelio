# Releasing Libtelio

This file documents the release process of libtelio.

## How a release is made

Releases are **tag-driven**: create a semver tag on the commit you want to release (for a
main-line release that's typically a commit that already passed nightly) and push it —
**no manual changelog preparation**:

```bash
git tag v8.1.0
git push origin v8.1.0
```

Pushing the tag triggers the release pipeline, which runs `ci/release.py` to:

1. **Generate the changelog** for the tag from the `.unreleased/` files at the tagged commit
   (via `ci/generate_changelog.py`) and insert it at the correct position in the changelog
   published to GitHub Pages at `/changelog/` (source of truth: the `gh-pages` branch — see
   [CONTRIBUTING.md](../CONTRIBUTING.md#updating-the-changelog)).
2. **Publish the GitLab release** with that changelog block as the release notes.
3. **Open a PR** against the branch the release was cut from (`main` or a `release/vX.Y`
   branch) that removes the consumed `.unreleased/` files and, on a **final** (non-`-rc`) tag,
   bumps `Cargo.toml` to the next version.

`ci/release.py` is run by the pipeline (not locally) and uses `GITHUB_WRITE_TOKEN` to publish
the changelog and open the PR.

### Version bumps (handled by the pipeline's PR)

- **`main`** → next **minor** by default (e.g. `v8.0.0` → `8.1.0`). Override with the
  `RELEASE_NEXT_VERSION` pipeline variable for the rare major.
- **`release/vX.Y`** → next **patch** (e.g. `v6.2.3` → `6.2.4`).
- **RC / pre-release tags** (`vX.Y.Z-rcN`) generate + publish the changelog and consume the
  `.unreleased/` files, but do **not** bump `Cargo.toml`.

### Release codename (series name)

Optional. Pass `RELEASE_SERIES_NAME` as a variable when running the manual `generate-release` job to set
the `### **Codename**` line; if omitted it defaults to empty (`### ****`).

### New minor lines

Releasing a new minor on an older line (e.g. `v6.3.0` when no `release/v6.3` exists) requires
creating that `release/vX.Y` branch first, then tagging on it.

## Manual changelog generation (local preview)

`ci/generate_changelog.py` aggregates the `.unreleased/` files into a version block. The
per-change files are kept separate to avoid merge conflicts on a shared changelog file on PRs.
For a local preview without writing or deleting anything:

```bash
python3 ci/generate_changelog.py --out-version "v1.2.3" --dry-run
```

- `--out-version` (e.g. `v1.2.3`) is required.
- `--out-series-name` sets the codename; if omitted it defaults to empty (`### ****`).
- `--out-file` is the changelog to insert into (the block is inserted at its semver-sorted
  position, not blindly prepended).
- `--no-delete` writes the changelog but keeps the `.unreleased/` files.

(The release pipeline drives this via `ci/release.py`, which imports these functions directly.)

Run `python3 ci/generate_changelog.py --help` for the full list.
