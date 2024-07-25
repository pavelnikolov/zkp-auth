FROM rust:1.79.0 AS builder
RUN apt-get update && apt-get install protobuf-compiler -y

WORKDIR /app
COPY . .
RUN cargo build --release --bin zkpauth-client

# use distroless image instead of alpine because rust uses musl libc
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/zkpauth-client /app/
USER 1000
CMD ["/app/zkpauth-client"]