// JWT verify benchmark for Bun: jose vs fast-jwt over bench/fixtures.json.
// Run from bench/bun:  bun run bench.ts [jose|fast-jwt] [iterations] [rounds]
// (impl default: both, "" also means both; iterations: decodes per timed round, default 10000;
// rounds default 1). Each case: 1,000 untimed warm-up decodes, then `rounds` timed loops of
// `iterations` decodes; the mean is over every timed decode.
import { jwtVerify } from "jose";
import { createVerifier } from "fast-jwt";
import { join } from "node:path";
import josePkg from "jose/package.json" with { type: "json" };
import fastJwtPkg from "fast-jwt/package.json" with { type: "json" };

interface Fixture {
  name: string;
  alg: string;
  key: string;
  token: string;
  token_len: number;
  audience: string;
  payload: Record<string, unknown>;
  expired_token: string; // exp a minute after iat, long past
  wrong_audience_token: string; // aud is another audience
}

interface Result {
  impl: string;
  name: string;
  token_len: number;
  key_len: number;
  iterations: number;
  rounds: number;
  ops_per_sec: number;
  mean_us: number;
  round_means_us: number[];
}

// Verifies a token, returning its payload (a promise of it if `async`).
type VerifyFn = (token: string) => unknown;

// The fields (e.g. `code`) the error a rejection throws must carry.
type ExpectedError = Record<string, string>;

interface Impl {
  id: string; // results file stem
  label: string; // "<lib> <version>"
  async: boolean;
  // What each case's verify must throw for its expired and wrong-audience tokens.
  rejects: { expired: ExpectedError; wrongAudience: ExpectedError };
  // Builds the per-case verify closure; all setup happens here, outside timing.
  prepare(c: Fixture): Promise<VerifyFn>;
}

const WARMUP = 1_000;

const BENCH_DIR = join(import.meta.dir, "..");
const FIXTURES = join(BENCH_DIR, "fixtures.json");
const RESULTS_DIR = join(BENCH_DIR, "results");

const HMAC_HASHES: Record<string, string> = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };

// jose imports a raw (Uint8Array) secret with crypto.subtle.importKey on every verify; a CryptoKey
// is imported once, as importSPKI does for a PEM.
function hmacKey(secret: string, alg: string): Promise<CryptoKey> {
  const hash = HMAC_HASHES[alg];
  if (hash === undefined) throw new Error(`not an HMAC algorithm: ${alg}`);
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash }, false, ["verify"]);
}

const impls: Impl[] = [
  {
    id: "jose",
    label: `jose ${josePkg.version}`,
    async: true,
    rejects: {
      expired: { code: "ERR_JWT_EXPIRED" },
      wrongAudience: { code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "aud" },
    },
    async prepare(c) {
      const key = await hmacKey(c.key, c.alg);
      const opts = { algorithms: [c.alg], audience: c.audience };
      return (token) => jwtVerify(token, key, opts).then((r) => r.payload);
    },
  },
  {
    id: "fast-jwt",
    label: `fast-jwt ${fastJwtPkg.version}`,
    async: false,
    rejects: {
      expired: { code: "FAST_JWT_EXPIRED" },
      wrongAudience: { code: "FAST_JWT_INVALID_CLAIM_VALUE" },
    },
    async prepare(c) {
      const verify = createVerifier({
        key: c.key,
        // fixtures are all HS256; fast-jwt's Algorithm union is narrower than string
        algorithms: [c.alg as "HS256"],
        allowedAud: c.audience,
        cache: false,
      });
      return (token) => verify(token);
    },
  },
];

// Nanoseconds for `n` decodes of `token`, in one loop.
async function runBatch(fn: VerifyFn, token: string, n: number, isAsync: boolean): Promise<number> {
  const t0 = Bun.nanoseconds();
  if (isAsync) {
    for (let i = 0; i < n; i++) await fn(token);
  } else {
    for (let i = 0; i < n; i++) fn(token);
  }
  return Bun.nanoseconds() - t0;
}

// Throws unless `fn` rejects `token` with an error carrying every field of `expected`.
async function checkRejects(fn: VerifyFn, token: string, expected: ExpectedError, where: string, what: string): Promise<void> {
  let error: unknown;
  try {
    await fn(token);
  } catch (e) {
    error = e;
  }
  if (error === undefined) throw new Error(`${where}: accepted ${what}`);
  const fields = error as Record<string, unknown>;
  if (!Object.entries(expected).every(([k, v]) => fields[k] === v)) {
    throw new Error(`${where}: rejected ${what} with the wrong error (wanted ${JSON.stringify(expected)}): ${error}`);
  }
}

async function benchCase(impl: Impl, c: Fixture, iterations: number, rounds: number): Promise<Result> {
  const fn = await impl.prepare(c);
  const token = c.token;
  const where = `${impl.label} ${c.name}`;

  // Correctness checks: decodes the token, rejects an expired one and another audience's.
  const decoded = await fn(token);
  if (!Bun.deepEquals(decoded, c.payload, true)) {
    throw new Error(`${where}: decoded payload mismatch`);
  }
  await checkRejects(fn, c.expired_token, impl.rejects.expired, where, "an expired token");
  await checkRejects(fn, c.wrong_audience_token, impl.rejects.wrongAudience, where, "another audience's token");

  await runBatch(fn, token, WARMUP, impl.async);

  const roundNs: number[] = [];
  for (let r = 0; r < rounds; r++) roundNs.push(await runBatch(fn, token, iterations, impl.async));
  const meanNs = roundNs.reduce((a, b) => a + b, 0) / (iterations * rounds);

  return {
    impl: impl.label,
    name: c.name,
    token_len: c.token_len,
    key_len: Buffer.byteLength(c.key, "utf8"),
    iterations,
    rounds,
    ops_per_sec: Math.round(1e9 / meanNs),
    mean_us: +(meanNs / 1e3).toFixed(3),
    round_means_us: roundNs.map((ns) => +(ns / iterations / 1e3).toFixed(3)),
  };
}

// The min–max of a row's round means, e.g. "1.234–1.301".
function roundSpread(r: Result): string {
  return `${Math.min(...r.round_means_us).toFixed(3)}–${Math.max(...r.round_means_us).toFixed(3)}`;
}

function printTable(label: string, rows: Result[], rounds: number): void {
  const cols: (keyof Result)[] = ["name", "token_len", "iterations", "rounds", "mean_us"];
  const headers: string[] = [...cols];
  const cells = rows.map((r) => cols.map((k) => (typeof r[k] === "number" ? r[k].toLocaleString("en-US") : String(r[k]))));
  if (rounds > 1) {
    headers.push("round_means_us");
    rows.forEach((r, i) => cells[i]!.push(roundSpread(r)));
  }
  const widths = headers.map((k, i) => Math.max(k.length, ...cells.map((row) => row[i]!.length)));
  const fmt = (row: string[]) =>
    row.map((v, i) => (i < 1 ? v.padEnd(widths[i]!) : v.padStart(widths[i]!))).join("  ");
  console.log(label);
  console.log(fmt(headers));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const row of cells) console.log(fmt(row));
  console.log();
}

const [, , only = "", iterationsArg = "10000", roundsArg = "1"] = Bun.argv;
const ITERATIONS = Number(iterationsArg);
const ROUNDS = Number(roundsArg);
for (const [what, n] of [["iterations", ITERATIONS], ["rounds", ROUNDS]] as const) {
  if (!Number.isInteger(n) || n < 1) throw new Error(`${what} must be a positive integer, got ${n}`);
}
const selected = only === "" ? impls : impls.filter((i) => i.id === only);
if (selected.length === 0) {
  throw new Error(`unknown impl ${only}; expected one of: ${impls.map((i) => i.id).join(", ")}`);
}

const fixtures = (await Bun.file(FIXTURES).json()) as Fixture[];
console.log(`Bun ${Bun.version}, ${fixtures.length} cases\n`);

for (const impl of selected) {
  const rows: Result[] = [];
  for (const c of fixtures) rows.push(await benchCase(impl, c, ITERATIONS, ROUNDS));
  await Bun.write(join(RESULTS_DIR, `${impl.id}.json`), JSON.stringify(rows, null, 2) + "\n");
  printTable(impl.label, rows, ROUNDS);
}
