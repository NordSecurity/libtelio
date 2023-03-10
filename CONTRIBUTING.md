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

## Licensing
Libtelio is released under GPL-3.0 License. For more details please refer to [LICENSE.md](LICENSE.md). 

## Contributing Documents
Before we can accept your pull request we may need you to submit documents (e.g., DCO, CLA) that either be provided automatically or manually by us. 
In any case, we will guide you through and provide you with the support, if needed.

## Code of conduct
Nord Security and all of it's projects adhere to the [Contributor Covenant Code of Conduct](https://github.com/NordSecurity/.github/blob/master/CODE_OF_CONDUCT.md). When participating, you are expected to honor this code.

## Thank you!
