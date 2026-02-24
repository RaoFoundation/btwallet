.PHONY: fmt fmt-check clippy clippy-all test package check

# Auto-format code (nightly rustfmt)
fmt:
	rustup run nightly cargo fmt --all

# Check formatting without changes
fmt-check:
	rustup run nightly cargo fmt --check --all

# Lint with default features (no pyo3)
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Lint with all features (including pyo3)
clippy-all:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run unit tests (skip doctests)
test:
	cargo test --workspace --all-features --lib --tests

# Verify crate packaging
package:
	cargo package --no-verify --allow-dirty

# Run all checks sequentially
check: fmt-check clippy clippy-all test package
