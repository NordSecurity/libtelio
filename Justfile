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

nightly := "nightly-2024-04-23"
rust1_80 := "1.80.0"

# Run all rust tests
test:
    cargo test --all --quiet

# Run clippy
clippy:
    cargo clippy --lib -- --deny warnings --allow unknown-lints -W clippy::expect_used -W clippy::panic -W clippy::unwrap_used

# Run udeps
udeps: _udeps-install
    cargo +{{ nightly }} udeps --workspace --locked --output human --backend depinfo

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
prepush: test clippy udeps unused deny black pylint

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

# Start a dev web cgi server, for local teliod cgi development
web:
    @echo "Go to http://127.0.0.1:8080/cgi-bin/teliod.cgi"
    python3 -m http.server --cgi -d $(pwd)/contrib/http_root/ -b 127.0.0.1 8080

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

_udeps-install: _nightly-install
    cargo +{{ nightly }} install cargo-udeps@0.1.47 --locked

_unused-install: _rust1_80-install
    cargo +{{ rust1_80 }} install --version 0.2.0 cargo-unused-features --locked

_deny-install:
    cargo install --locked cargo-deny@0.15.1

_nightly-install:
    rustup toolchain add {{ nightly }}

_rust1_80-install:
    rustup toolchain add {{ rust1_80}}
