.PHONY: build build-all test run docker-build docker-run clean fmt fmt-check clippy deny audit proto run-local

# Default feature set: in-house threshold signing.
FEATURES ?= in-house

build:
	cargo build --release --no-default-features --features $(FEATURES)

# Build all four custody-provider feature combinations (mirrors CI matrix).
build-all:
	@for f in in-house fireblocks dfns turnkey; do \
		echo "==> cargo build --features $$f"; \
		cargo build --release --no-default-features --features $$f || exit 1; \
	done

test:
	cargo llvm-cov --codecov --output-path codecov.json

run:
	cargo run --release --no-default-features --features $(FEATURES)

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

deny:
	cargo deny check

audit:
	cargo audit

proto:
	cargo build -p mpc-signing-service --build

# Bring up three local signing nodes (stub; Stage 8 wires real mTLS clustering).
run-local:
	bash scripts/run-mpc-node.sh

docker-build:
	docker build -t ai-crypto-onramp/mpc-signing-service .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/mpc-signing-service

clean:
	cargo clean
	rm -f codecov.json