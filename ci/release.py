#!/usr/bin/env python3
"""Release step run by the pipeline on a semver tag

It:
  1. finds the branch the tag was cut from (main or release/vX.Y)
  2. builds the changelog block from the tagged commit's .unreleased/ files and adds it,
     in order, to changelog.md on the gh-pages branch, then triggers a Pages redeploy
  3. writes the raw block to --block-out (used for the GitLab release notes),
  4. opens a PR on the source branch to remove the used .unreleased/ files and, on a
     final (non-rc) tag, bump Cargo.toml.

Needs GITHUB_WRITE_TOKEN. Imports generate_changelog and github_helpers (same dir).
"""

import argparse
import os
import re
import tempfile

import tomlkit

import generate_changelog as gc
from github_helpers import git_clone, github_api_request, has_changes, run

GH_PAGES_BRANCH = "gh-pages"
CHANGELOG_UPDATED_EVENT = "changelog-updated"
# Accepted release tags: a final vX.Y.Z or a pre-release vX.Y.Z-rcN
RELEASE_TAG_REGEX = re.compile(r"^v\d+\.\d+\.\d+(-rc\d+)?$")
DEFAULT_LIBTELIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_final_tag(tag: str) -> bool:
    """True for a final release (v8.1.0), False for a pre-release (v8.0.0-rc2)."""
    return bool(re.match(r"^v\d+\.\d+\.\d+$", tag))


def resolve_source_branch_for_tag(github_repo: str, tag: str) -> str:
    """Return the branch the tag was cut from: release/vX.Y if it exists, else main."""
    version_prefix = re.match(r"^(v\d+\.\d+)", tag)
    if not version_prefix:
        return "main"
    branch = f"release/{version_prefix.group(1)}"
    refs = run(
        "git", "ls-remote", "--heads", f"https://github.com/{github_repo}.git", branch
    )
    return branch if refs.strip() else "main"


def next_cargo_version(tag: str, source_branch: str, override: str) -> str:
    if override:
        return override.lstrip("v")
    major, minor, patch = (int(x) for x in tag.lstrip("v").split("-")[0].split("."))
    if source_branch == "main":
        return f"{major}.{minor + 1}.0"  # next minor
    return f"{major}.{minor}.{patch + 1}"  # next patch


def get_cargo_version(cargo_path: str) -> str:
    """Read the [package] version from Cargo.toml."""
    with open(cargo_path, "r", encoding="utf-8") as f:
        doc = tomlkit.parse(f.read())
    return str(doc["package"]["version"])


def set_cargo_version(cargo_path: str, new_version: str) -> None:
    """Set the [package] version in Cargo.toml"""
    with open(cargo_path, "r", encoding="utf-8") as f:
        doc = tomlkit.parse(f.read())
    doc["package"]["version"] = new_version
    with open(cargo_path, "w", encoding="utf-8") as f:
        f.write(tomlkit.dumps(doc))


def build_and_insert_block(
    unreleased_dir: str, changelog_path: str, tag: str, series: str
):
    """Build the block from .unreleased (without deleting) and insert it into the changelog.
    Returns the block, or None if there were no entries."""
    block = gc.gather_output(unreleased_dir, tag, series, delete_files=False)
    if block is None:
        return None
    gc.insert_block_into_file(changelog_path, block, tag)
    return block


def update_gh_pages(args, token, tmp) -> str:
    """Clone gh-pages, insert the block into changelog.md, push, and return the block."""
    gh = os.path.join(tmp, "gh-pages")
    git_clone(args.github_repo, GH_PAGES_BRANCH, gh, token)

    block = build_and_insert_block(
        os.path.join(args.libtelio_dir, ".unreleased"),
        os.path.join(gh, "changelog.md"),
        args.tag,
        args.series_name,
    )
    if block is None:
        print("No changelog entries generated (empty .unreleased); nothing to publish.")
        return ""

    if args.dry_run:
        dump = os.path.abspath("dry-run-changelog.md")
        run("cp", os.path.join(gh, "changelog.md"), dump)
        print(
            f"DRY-RUN: not pushing gh-pages, not firing dispatch. Full result: {dump}"
        )
        print(
            run("git", "--no-pager", "diff", "--", "changelog.md", cwd=gh)
            or "(no diff)"
        )
        return block

    if has_changes(gh):
        run("git", "add", "changelog.md", cwd=gh)
        run("git", "commit", "-m", f"Add changelog for {args.tag}", cwd=gh)
        run("git", "push", "origin", GH_PAGES_BRANCH, cwd=gh)
        status, _ = github_api_request(
            "POST",
            args.github_repo,
            "dispatches",
            token,
            {"event_type": CHANGELOG_UPDATED_EVENT},
        )
        if status == 204:
            print(f"repository_dispatch {CHANGELOG_UPDATED_EVENT}: OK")
        else:
            print(
                f"WARNING: repository_dispatch {CHANGELOG_UPDATED_EVENT} failed (HTTP {status}); "
                "Pages may need a manual redeploy."
            )
    return block


def open_cleanup_pr(args, token, source_branch, tmp) -> None:
    """PR on source_branch: remove used .unreleased/ files (+ Cargo bump on final tags)."""
    unreleased = os.path.join(args.libtelio_dir, ".unreleased")
    # The dir may be gone if a previous release used the last file; then nothing to remove.
    consumed = sorted(os.listdir(unreleased)) if os.path.isdir(unreleased) else []
    src = os.path.join(tmp, "src")
    git_clone(args.github_repo, source_branch, src, token)

    pr_branch = f"auto/release-clean-up-{args.tag}"
    run("git", "checkout", "-b", pr_branch, cwd=src)
    for name in consumed:
        run("git", "rm", "--ignore-unmatch", f".unreleased/{name}", cwd=src)

    actions = []
    if is_final_tag(args.tag):
        cargo_path = os.path.join(src, "Cargo.toml")
        new_version = next_cargo_version(args.tag, source_branch, args.next_version)
        current_version = get_cargo_version(cargo_path)
        if gc.version_key(new_version) <= gc.version_key(current_version):
            raise RuntimeError(
                f"Refusing to bump {source_branch} Cargo.toml from {current_version} to "
                f"{new_version}: not a forward bump. Releasing an older tag, or is the branch "
                f"already ahead? Provide a higher RELEASE_NEXT_VERSION if this is intentional."
            )
        set_cargo_version(cargo_path, new_version)
        run("git", "add", "Cargo.toml", cwd=src)
        actions.append(f"bump to {new_version}")
    actions.append("clean up .unreleased")
    summary = f"{' and '.join(actions)} for {args.tag}"
    summary = summary[0].upper() + summary[1:]

    if not has_changes(src):
        print("Nothing to clean up / bump; skipping PR.")
        return

    # libtelio CI requires every PR to touch .unreleased/
    unreleased_dst = os.path.join(src, ".unreleased")
    os.makedirs(unreleased_dst, exist_ok=True)
    placeholder = f"clean_up_released_tag_{args.tag}"
    with open(os.path.join(unreleased_dst, placeholder), "w", encoding="utf-8"):
        pass
    run("git", "add", f".unreleased/{placeholder}", cwd=src)

    if args.dry_run:
        print(
            f"DRY-RUN: not committing/pushing, not opening PR. Title would be: {summary!r}"
        )
        print(
            run("git", "--no-pager", "diff", "--cached", cwd=src)
            or "(no staged changes)"
        )
        return

    run("git", "commit", "-m", summary, cwd=src)
    run("git", "push", "--force", "origin", f"{pr_branch}:{pr_branch}", cwd=src)

    status, body = github_api_request(
        "POST",
        args.github_repo,
        "pulls",
        token,
        {
            "title": summary,
            "head": pr_branch,
            "base": source_branch,
            "body": (
                f"Automated post-release cleanup for `{args.tag}` "
                f"(source branch `{source_branch}`).\n\n"
                "- Removes the `.unreleased/` files consumed by this release."
                + (
                    "\n- Bumps `Cargo.toml` to the next version."
                    if is_final_tag(args.tag)
                    else ""
                )
            ),
        },
    )
    if status == 201:
        print(f"Opened PR: {body.get('html_url')}")
    elif status == 422:
        print(f"PR already exists for {pr_branch} (HTTP 422); pushed updated branch.")
    else:
        raise RuntimeError(f"Failed to open PR: HTTP {status}: {body}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag", required=True, help="Release tag, e.g. v8.1.0 or v8.0.0-rc2"
    )
    parser.add_argument(
        "--libtelio-dir",
        default=DEFAULT_LIBTELIO_DIR,
        help="Path to the libtelio checkout (at the released commit)",
    )
    parser.add_argument(
        "--github-repo",
        default="NordSecurity/libtelio",
        help="owner/repo of the GitHub repository",
    )
    parser.add_argument(
        "--series-name", default="", help="Release codename (RELEASE_SERIES_NAME)"
    )
    parser.add_argument(
        "--next-version",
        default="",
        help="Explicit next Cargo version (RELEASE_NEXT_VERSION); overrides the default",
    )
    parser.add_argument(
        "--block-out",
        default="release_block.md",
        help="File to write the raw version block to (for release notes + announce)",
    )
    parser.add_argument(
        "--skip-pr",
        action="store_true",
        help="Update gh-pages only; do not open the cleanup/bump PR",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do everything locally (clone, build, insert, bump) but make no "
        "remote writes: no gh-pages push, no dispatch, no PR",
    )
    args = parser.parse_args()

    if not RELEASE_TAG_REGEX.match(args.tag):
        raise SystemExit(
            f"Invalid release tag {args.tag!r}. Expected vX.Y.Z or vX.Y.Z-rcN "
            "(e.g. v8.1.0 or v8.0.0-rc2)."
        )

    token = os.environ.get("GITHUB_WRITE_TOKEN", "")
    if not token and not args.dry_run:
        raise SystemExit("GITHUB_WRITE_TOKEN is required (or pass --dry-run).")
    source_branch = resolve_source_branch_for_tag(args.github_repo, args.tag)
    print(
        f"Release {args.tag} cut from branch: {source_branch} "
        f"({'final' if is_final_tag(args.tag) else 'pre-release'})"
    )

    with tempfile.TemporaryDirectory() as tmp:
        block = update_gh_pages(args, token, tmp)

        with open(args.block_out, "w", encoding="utf-8") as f:
            f.write(block or "")
        print(f"Wrote release block to {args.block_out}")

        if args.skip_pr:
            print("--skip-pr set; not opening cleanup PR.")
            return
        open_cleanup_pr(args, token, source_branch, tmp)


if __name__ == "__main__":
    main()
