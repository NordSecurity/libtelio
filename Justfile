set shell := ["sh", "-c"]

# Aliases to be used only in interactive mode, please use full names when calling
# just in scripts or gitlab jobs.

[private]
alias t := test
[private]
alias c := clippy
[private]
alias u := udeps
[private]
alias un := unused
[private]
alias d := deny
[private]
alias p := prepush

nightly := "nightly-2025-03-26"
rust_stable := "1.89.0"

# Run all rust tests
test:
    cargo test --all --quiet

# Run clippy
clippy package="" features="": _clippy-install
    cargo clippy {{ if package == "" {"--lib"} else {"--package=" + package} }} {{ if features == "" {""} else {"--features=" + features} }} -- --deny warnings --allow unknown-lints -W clippy::expect_used -W clippy::panic -W clippy::unwrap_used -W clippy::indexing_slicing -W clippy::await_holding_lock -W clippy::large_futures

# Run udeps
udeps: _udeps-install
    cargo +{{ nightly }} udeps --workspace --locked --output human --backend depinfo --release

# Run unused features
unused: _unused-install
    #!/usr/bin/env bash
    set -euxo pipefail
    for dir in ./crates/* ./clis/*; do
        pushd "$dir"
        unused-features analyze -l debug
        unused-features prune -l debug
        popd
    done
    git restore Cargo.lock
    if ! git diff --quiet; then
        git diff
        exit 1
    fi

# Run deny
deny: _deny-install
    cargo deny check

# Run rust pre-push checks
prepush: test clippy udeps unused deny python_checks format_markdown

python_checks: black pylint isort mypy autoflake

# Run the black python linter
[working-directory: 'nat-lab']
black fix="false":
    #!/usr/bin/env bash
    set -euxo pipefail
    if [[ {{fix}} == "true" ]]; then
        uv run --isolated black --color . && uv run --isolated black --color ../ci
    else
        uv run --isolated black --check --diff --color . && uv run --isolated black --check --diff --color ../ci
    fi

# Run the pylint linter
[working-directory: 'nat-lab']
pylint:
    uv run --isolated pylint -f colorized . --ignore telio_bindings.py

# Run the isort linter
[working-directory: 'nat-lab']
isort:
    uv run --isolated isort --check-only --diff .

# Run mypy type checker
[working-directory: 'nat-lab']
mypy:
    uv run --isolated mypy .

# Run the autoflake linter
[working-directory: 'nat-lab']
autoflake:
    uv run --isolated autoflake --quiet --check .

format_markdown fix="false":
    #!/usr/bin/env bash
    set -euxo pipefail
    if [[ {{fix}} == "true" ]]; then
        docker run -v $PWD:/workdir davidanson/markdownlint-cli2:v0.18.1 --fix
    else
        docker run -v $PWD:/workdir davidanson/markdownlint-cli2:v0.18.1 
    fi

diagram:
    uv run --isolated --with pyyaml==6.0.2 nat-lab/utils/generate_network_diagram.py nat-lab/docker-compose.yml nat-lab/network.md

_udeps-install: _nightly-install
    cargo +{{ nightly }} install cargo-udeps@0.1.55 --locked

_unused-install: _rust_stable-install _rust-from-toolchain-file-install
    cargo +{{ rust_stable }} install --version 0.2.0 cargo-unused-features --locked

_deny-install:
    cargo install --locked cargo-deny@0.18.9

_nightly-install:
    rustup toolchain add {{ nightly }}

_rust_stable-install:
    rustup toolchain add {{ rust_stable }}

_rust-from-toolchain-file-install:
    rustup toolchain install

_clippy-install:
    rustup component add clippy
