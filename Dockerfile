FROM rust:1.80 AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/mpc-signing-service /server
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/server"]