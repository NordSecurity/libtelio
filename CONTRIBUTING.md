# Contributing

We happily accept both issues and pull requests for bug reports, bug fixes, feature requests, features implementations and documentation improvements.

For new features we recommend that you create an issue first so the feature can be discussed and to prevent unnecessary work in case it's not a feature we want to support. Although, we do realize that sometimes code needs to be in place to allow for a meaningful discussion so creating an issue upfront is not a requirement.

## Building and testing

The steps for how to build and test libtelio are described in the [README](README.md)

## PR workflow

We want to get your changes merged as fast as possible, and we know you want that too. To help with this there are a few things you can do to speed up the process:

### Build, test and lint locally

The local feedback cycle is faster than waiting for the CI. Make sure your changes can be built locally and that tests, rustfmt and clippy all pass locally. A green CI is a happy CI.

### PR Hygiene

On top of the CI being green, every PR will go through code review, and you can help us speed up the review process by making your PR easier to review. Here are some guidelines:

**Small PRs are easier to review than big PRs**, so try to keep your PRs small and focused. To achieve that, try to make sure you PR doesn't contain multiple unrelated changes and if you are doing some bigger feature work, try to split the work into multiple smaller PRs that solve the problem together.

**A clean history can make things easier**. Some PRs are easier to review commit-by-commit, rather than looking at the full changelist in one go. To enable that, prefer `rebase` over `merge` when updating your branch. Keeping PRs small and short-lived will also help keep your history clean since there's less time for upstream to change that much.

### Commit message requirements

Read [requirements](docs/git_commit_messages_requirements.md)

### Updating The Changelog

In the past we would write changelog entries directly to `changelog.md`. This led to "changelog merge conflict madness" since whenever a PR with some change to the changelog was merged, any other PR that updated the changelog would have merge conflicts to resolve. To solve this problem we moved to a setup where developers create a file in `.unreleased` and place their changelog entry there, and then when a release is made the changelog is generated from those files.

The naming convention for files in `.unreleased` is as follows:

- If your change is related to a ticket, name the file the same as the ticket number (e.g. `LLT-1234`)
- If your change is not related to a ticket, use a short sentence to describe the change, as snake case (e.g. `bump_rustls-webpki_RUSTSEC-2026-0104`)

When a release is made, the **release pipeline** runs `ci/generate_changelog.py`, which takes the files in `.unreleased` and generates a version block (each non-empty file becomes an entry like `<ticket>: <file contents>`). The pipeline inserts that block at the correct position in the published changelog and then opens a PR that removes the consumed `.unreleased` files (so they don't carry into the next release). You no longer run this at release time by hand — just add your `.unreleased` entry in your PR. See [docs/releasing.md](docs/releasing.md) for the full release flow.

There is **no `changelog.md` in the repo** anymore. The compiled changelog for all released versions is published to GitHub Pages at `/changelog/`, next to the rustdoc API docs; its source of truth is the `changelog.md` file on the [`gh-pages`](https://github.com/NordSecurity/libtelio/tree/gh-pages) branch (not `main`), which the release pipeline updates and `.github/workflows/gh-pages.yml` renders to HTML and deploys. Keeping it off `main` lets the pipeline update it without a PR against `main`. Add your changelog entry to `.unreleased` as described above — never edit the published changelog by hand.

Not all PRs need an addition to the changelog. The changelog is our way of communicating to the apps about changes since the last version, so only changes that are of interest or concern to the apps need to actually have something show up in the changelog. However, to remind you that you may have to add something to the changelog, the CI pipeline requires that you add a file to `.unreleased` in every PR. It is up to both the implementer(s) and the reviewers of a PR to make sure that the file in `.unreleased` has the "right" content for the PR, whether that be leaving it empty because the apps don't care or leaving an accurate description of what has changed.

Some (non-exhaustive) examples of what should end up in the changelog:

- Added, updated or removed features
- Dependency updates that either fix bugs or change behavior
- CI changes that affect the resulting artifacts (e.g. when we added CFG to windows builds or adding support for 16k page sizes for android, etc.)

Some (non-exhaustive) examples of what shouldn't end up in the changelog:

- Changes that only touch tests
- Dependency updates that don't fix bugs or change behavior
- CI changes that don't affect the resulting artifacts (e.g. updating docker images for natlab, changing rust toolchain for fuzzing jobs, etc.)

#### Directory Structure

```plaintext
├── .unreleased<br>
│   ├── LLT-0001<br>
│   ├── LLT-0002<br>
│   ├── clean_changelog_without_ticket<br>
│   ├── EXT-001<br>
│   ├── LLT-0054<br>
│   ├── ...<br>
└── ci/generate_changelog.py<br>
```

(The published `changelog.md` is not in this repo — it lives on the `gh-pages` branch; see above.)

## Licensing

Libtelio is released under GPL-3.0 License. For more details please refer to [LICENSE.md](LICENSE.md).

## Contributing Documents

Before we can accept your pull request we may need you to submit documents (e.g., DCO, CLA) that either be provided automatically or manually by us.
In any case, we will guide you through and provide you with the support, if needed.

## Code of conduct

Nord Security and all of it's projects adhere to the [Contributor Covenant Code of Conduct](https://github.com/NordSecurity/.github/blob/master/CODE_OF_CONDUCT.md). When participating, you are expected to honor this code.

## Thank you
