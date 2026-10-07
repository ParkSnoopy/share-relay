FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

COPY --from=builder --chown=65532:65532 /build/target/release/share-relay /usr/local/bin/share-relay
RUN install -d -m 0700 -o 65532 -g 65532 /var/lib/snoo-box-share
LABEL io.parksnoopy.share-relay.api="1"

USER 65532:65532
EXPOSE 6697
ENTRYPOINT ["/usr/local/bin/share-relay"]
