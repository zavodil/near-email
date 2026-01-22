FROM rust:1.85-bookworm as builder

WORKDIR /app
COPY . .
RUN cargo update home --precise 0.5.9 && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/db-api /usr/local/bin/

EXPOSE 8080
CMD ["db-api"]
