set dotenv-load := false

# Verify toolchain and prefetch locked dependencies
setup:
    rustc --version
    cargo --version
    cargo fetch --locked

# Run the CLI in human mode
run *args:
    cargo run --bin agent-auth -- {{args}}

# Run the CLI in agent-facing mode
run-ai *args:
    AGENT=1 cargo run --bin agent-auth -- {{args}}

# Apply formatting
fmt:
    cargo fmt --all

# Fail on unformatted files without rewriting them
fmt-check:
    cargo fmt --all -- --check

# Run Clippy with warnings as errors
lint:
    cargo clippy --all-targets --locked -- -D warnings

# Run the full test suite and doctests
test:
    cargo test --all-targets --locked
    cargo test --doc --locked

# Run only tests whose transitive inputs changed relative to base
test-affected base="main":
    #!/usr/bin/env bash
    set -euo pipefail
    changed=""
    if git rev-parse --verify "{{base}}" >/dev/null 2>&1; then
        changed="$(git diff --name-only "{{base}}...HEAD" 2>/dev/null || true)"
    fi
    dirty="$(git status --porcelain | awk '{print $NF}')"
    files="$(printf '%s\n%s\n' "$changed" "$dirty" | sed '/^$/d' | sort -u)"
    if [ -z "$files" ]; then
        echo "No changed files detected relative to {{base}}; running full test suite."
        cargo test --all-targets --locked
        cargo test --doc --locked
        exit 0
    fi
    run_full=0
    run_skill=0
    targets=()
    while IFS= read -r file; do
        case "$file" in
            README.md|AGENTS.md|LICENSE|.gitignore|.github/*)
                ;;
            skills/*)
                run_skill=1
                ;;
            Cargo.toml|Cargo.lock|src/*)
                run_full=1
                ;;
            tests/*.rs)
                name="$(basename "$file" .rs)"
                targets+=("$name")
                ;;
            *)
                run_full=1
                ;;
        esac
    done <<< "$files"
    if [ "$run_full" -eq 1 ]; then
        echo "Selected tests: full suite (--all-targets + doctests)"
        cargo test --all-targets --locked
        cargo test --doc --locked
        exit 0
    fi
    if [ "$run_skill" -eq 0 ] && [ "${#targets[@]}" -eq 0 ]; then
        echo "No test targets affected by changed files."
        exit 0
    fi
    if [ "$run_skill" -eq 1 ]; then
        targets+=("skill")
    fi
    unique_targets=($(printf '%s\n' "${targets[@]}" | sort -u))
    echo "Selected integration test targets: ${unique_targets[*]}"
    for t in "${unique_targets[@]}"; do
        cargo test --test "$t" --locked
    done

# Run test suite with 90% line and function coverage gates
coverage:
    mkdir -p .tmp
    cargo llvm-cov --all-targets --locked --fail-under-lines 90 --fail-under-functions 90 --json --output-path .tmp/coverage-final.json

# Validate without modifying files
check: fmt-check lint test coverage

# Build the release binary into bin/
build:
    cargo build --release --locked --bin agent-auth
    mkdir -p bin
    cp target/release/agent-auth bin/agent-auth
