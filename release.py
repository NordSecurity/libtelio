#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys


DRY_RUN = False


def execute_command(command):
    print(f"$ {command}")
    if not DRY_RUN:
        return subprocess.run(command, shell=True, check=True)


def check_project_root_directory():
    if not os.path.isfile("Cargo.toml"):
        print("Not in project's root directory or Cargo.toml not found.")
        sys.exit(1)

    with open("Cargo.toml") as f:
        content = f.read()

    if not re.search(r"^\[package\]", content, re.MULTILINE) or not re.search(
        r'name\s*=\s*"telio"', content
    ):
        print('This does not appear to be a "libtelio" repo.')
        sys.exit(1)


def get_default_branch():
    default_branch = (
        subprocess.run(
            "git symbolic-ref refs/remotes/origin/HEAD",
            capture_output=True,
            text=True,
            shell=True,
        )
        .stdout.strip()
        .replace("refs/remotes/origin/", "")
    )

    if not default_branch:
        print("Failed to retrieve default branch.")
        sys.exit(1)

    return default_branch


def check_git_tree(branch):
    current_branch = subprocess.run(
        "git rev-parse --abbrev-ref HEAD",
        capture_output=True,
        text=True,
        shell=True,
    ).stdout.strip()

    if current_branch != branch:
        print("Git tree is not on the default branch.")
        sys.exit(1)

    git_status = subprocess.run(
        "git status --short",
        capture_output=True,
        text=True,
        shell=True,
    ).stdout.strip()

    if git_status:
        print("Git tree is dirty.")
        sys.exit(1)


def check_existing_tag(tag):
    existing_tags = (
        subprocess.run(
            "git tag --list",
            capture_output=True,
            text=True,
            shell=True,
        )
        .stdout.strip()
        .split("\n")
    )

    if tag in existing_tags:
        print(f"Tag '{tag}' already exists in the git tree.")
        sys.exit(1)


def check_cargo_tools(install_missing_tools):
    cargo_output = subprocess.run(
        "cargo install --list",
        capture_output=True,
        text=True,
        shell=True,
    ).stdout

    if ("cargo-edit" not in cargo_output) or ("cargo-set-version" not in cargo_output):
        if install_missing_tools:
            if not DRY_RUN:
                cargo_install_output = subprocess.run(
                    "cargo install cargo-edit",
                    capture_output=True,
                    text=True,
                    shell=True,
                ).stdout

                if cargo_install_output.returncode != 0:
                    print("Failed to install 'cargo-edit'.")
                    sys.exit(1)
            else:
                print("$ cargo install cargo-edit")
        else:
            print(
                "Required tool 'cargo-edit' not found. Use --install-missing-tools to install."
            )
            sys.exit(1)


def validate_tag_format(tag):
    if not re.match(r"^v[0-9]+\.[0-9]+\.[0-9]+$", tag):
        print(
            "Invalid tag format. Expected format: 'vMAJOR.MINOR.BUGFIX', e.g. 'v4.12.3'."
        )
        sys.exit(1)


def update_changelog(tag):
    changelog_file = "./changelog.md"

    if not os.path.isfile(changelog_file):
        print("Changelog file not found.")
        sys.exit(1)

    if not DRY_RUN:
        with open(changelog_file) as f:
            content = f.read()

        content = re.sub(r"### UNRELEASED", tag, content, flags=re.IGNORECASE)

        with open(changelog_file, "w") as f:
            f.write(content)
    else:
        print(
            '$ substitute "### UNRELEASED" --> "### {}" in ./changelog.md'.format(tag)
        )


def update_cargo_toml(tag):
    execute_command(f"cargo set-version {tag.replace('v', '')} -p telio")


def commit_and_push(tag, push, remote, branch):
    execute_command(f"git add .")
    execute_command(f"git commit --message 'Release {tag}'")
    execute_command(f"git tag {tag}")

    if push:
        execute_command(f"git push {remote} {branch}")
        execute_command(f"git push {remote} --tags")


def main():
    parser = argparse.ArgumentParser(description="Libtelio release helper script")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode, only prints commands",
    )
    parser.add_argument(
        "--install-missing-tools",
        action="store_true",
        help="Install missing tools (e.g., 'cargo-edit')",
    )
    parser.add_argument("--tag", help="Version to release (mandatory)")
    parser.add_argument(
        "--push", action="store_true", help="Push changes to the remote repository"
    )
    parser.add_argument(
        "--changelog", action="store_true", help="Make changes to './changelog.md'"
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Remote name for git push (default: 'origin')",
    )
    parser.add_argument(
        "--branch",
        help="Remote name for git push (default repo branch will be used, if not supplied)",
    )
    args = parser.parse_args()

    if not args.tag:
        parser.error("The --tag argument is required.")

    global DRY_RUN
    if args.dry_run:
        DRY_RUN = True

    check_project_root_directory()

    branch = None
    if not args.branch:
        branch = get_default_branch()
    else:
        branch = args.branch

    check_git_tree(branch)
    check_existing_tag(args.tag)
    check_cargo_tools(args.install_missing_tools)
    validate_tag_format(args.tag)

    if args.changelog:
        update_changelog(args.tag)

    update_cargo_toml(args.tag)
    commit_and_push(args.tag, args.push, args.remote, branch)


if __name__ == "__main__":
    main()
