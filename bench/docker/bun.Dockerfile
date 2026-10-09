# jose and fast-jwt on Bun. Build context: bench/.
# The entrypoint runs the HS256 bench (bench.ts); the matrix services run matrix.ts.

FROM oven/bun:1.3.14-slim
WORKDIR /app/bench/bun
COPY bun/package.json bun/bun.lock ./
RUN bun install --frozen-lockfile --production
COPY bun/bench.ts bun/matrix.ts bun/tsconfig.json ./
COPY fixtures.json /app/bench/fixtures.json
COPY matrix/fixtures.json /app/bench/matrix/
COPY matrix/tls/ca.pem /app/bench/matrix/tls/
ENTRYPOINT ["bun", "run", "bench.ts"]
