# PyJWT, joserfc and ryjwt (dict with msgspec or jiter / msgspec Struct / pydantic BaseModel).
# Build context: the repo root.
# The entrypoint runs the HS256 bench (bench_python.py); the matrix services run bench_matrix.py.

FROM python:3.14.8-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1
ENV PATH=/root/.cargo/bin:$PATH
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /bin/uv
WORKDIR /src
COPY Cargo.toml Cargo.lock pyproject.toml uv.lock README.md ./
COPY src src
COPY python python
RUN uv build --wheel --out-dir /dist \
    && uv export --frozen --no-hashes --no-emit-project --only-group bench -o /dist/bench.txt

FROM python:3.14.8-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /bin/uv
RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    uv pip install --system --no-cache -r /dist/bench.txt /dist/ryjwt-*.whl
WORKDIR /app/bench
COPY bench/fixtures.json bench/bench_python.py bench/bench_matrix.py ./
COPY bench/matrix/fixtures.json matrix/
COPY bench/matrix/tls/ca.pem matrix/tls/
# the private keys sign the expired and wrong-audience tokens each library must reject
COPY bench/matrix/keys matrix/keys/
ENTRYPOINT ["yeet", "./bench_python.py"]
