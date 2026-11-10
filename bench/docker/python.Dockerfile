# PyJWT, joserfc and ryjwt (dict with msgspec or jiter / msgspec Struct / pydantic BaseModel).
# Build context: the repo root.
# The entrypoint runs the HS256 bench (bench_python.py); the matrix services run bench_matrix.py.

FROM python:3.14.8-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1
ENV PATH=/root/.cargo/bin:$PATH
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /bin/uv
WORKDIR /src
COPY Cargo.toml Cargo.lock pyproject.toml uv.lock README.md ./
COPY src src
COPY python python
# Built with profile-guided optimisation, as the released wheels are (.github/workflows/release.yml):
# an instrumented wheel trained on the CodSpeed benchmarks, then the wheel built with its profile,
# checked against it. For the host target given explicitly, so RUSTFLAGS reach only the extension's
# crates, not build scripts or proc macros.
COPY benchmarks benchmarks
COPY bench/matrix/keys bench/matrix/keys
COPY .github/scripts/pgo-train.sh .github/scripts/pgo-merge.sh .github/scripts/pgo-check.sh \
    .github/scripts/rustc-pgo.rs .github/scripts/
ENV UV_PYTHON_PREFERENCE=system
RUN set -eu; \
    export MATURIN_PEP517_ARGS="--target $(rustc -vV | sed -n 's/^host: //p')"; \
    RUSTFLAGS=-Cprofile-generate=/tmp/pgo uv build --wheel --out-dir /pgo/wheel; \
    sh .github/scripts/pgo-train.sh /pgo/wheel /pgo/raw; \
    sh .github/scripts/pgo-merge.sh /pgo/raw /pgo/ryjwt.profdata; \
    RUSTFLAGS="-Cprofile-use=/pgo/ryjwt.profdata -Cllvm-args=-pgo-warn-missing-function" \
        RUSTC_WRAPPER=/pgo/rustc_pgo RUSTC_PGO_LOG=/pgo/rustc-3.14.log \
        uv build --wheel --out-dir /dist; \
    sh .github/scripts/pgo-check.sh /pgo/rustc-3.14.log
RUN uv export --frozen --no-hashes --no-emit-project --only-group bench -o /dist/bench.txt

FROM python:3.14.8-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /bin/uv
RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    uv pip install --system --no-cache -r /dist/bench.txt /dist/ryjwt-*.whl
WORKDIR /app/bench
COPY bench/fixtures.json bench/bench_python.py bench/bench_matrix.py ./
COPY bench/matrix/fixtures.json matrix/
COPY bench/matrix/tls/ca.pem matrix/tls/
# the private keys sign the expired and wrong-audience tokens each library must reject
COPY bench/matrix/keys matrix/keys/
ENTRYPOINT ["yeet", "./bench_python.py"]
