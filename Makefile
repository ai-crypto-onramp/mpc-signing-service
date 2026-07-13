.PHONY: build build-matrix test test-all coverage lint fmt fmt-check run \
	docker-build docker-run docker-up docker-down clean

build:
	cargo build --release

# The four feature combinations the plan requires to compile (Stage 1).
build-matrix:
	cargo build --no-default-features --features in-house
	cargo build --no-default-features --features fireblocks
	cargo build --no-default-features --features dfns
	cargo build --no-default-features --features turnkey

test:
	cargo test

test-all:
	cargo test --all-features

coverage:
	cargo llvm-cov --all-features --codecov --output-path codecov.json

lint:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

run:
	cargo run --release

docker-build:
	docker build -t ai-crypto-onramp/mpc-signing-service .

docker-run:
	docker run --rm -p 8080:8080 -p 9090:9090 ai-crypto-onramp/mpc-signing-service

docker-up:
	docker compose up -d --wait

docker-down:
	docker compose down

clean:
	cargo clean
	rm -f codecov.json
