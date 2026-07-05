.PHONY: build test run docker-build docker-run clean

build:
	cargo build --release

test:
	cargo test

run:
	cargo run --release

docker-build:
	docker build -t ai-crypto-onramp/mpc-signing-service .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/mpc-signing-service

clean:
	cargo clean
