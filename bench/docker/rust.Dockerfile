# jsonwebtoken (aws-lc-rs). Build context: bench/.
# The entrypoint runs the HS256 bench (jwt_bench); the matrix service runs jwt_matrix.

FROM rust:1.98.1-slim AS build
WORKDIR /app/bench/rust
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src src
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=build /app/bench/rust/target/release/jwt_bench /app/bench/rust/target/release/jwt_matrix /usr/local/bin/
WORKDIR /app/bench
COPY fixtures.json ./
COPY matrix/fixtures.json matrix/
# The binaries find their fixtures and results/ relative to their build-time manifest dir, rust/.
RUN mkdir rust
ENTRYPOINT ["jwt_bench"]
