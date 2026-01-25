FROM rust:1.84-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo update home --precise 0.5.9 && \
    cargo update zip --precise 2.2.0 && \
    cargo update time --precise 0.3.36 && \
    cargo update time-core --precise 0.1.2 && \
    cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/db-api /usr/local/bin/

EXPOSE 8080
CMD ["db-api"]
