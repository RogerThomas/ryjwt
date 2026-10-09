// JWT verify benchmark for Bun: jose vs fast-jwt over bench/fixtures.json.
// Run from bench/bun:  bun run bench.ts [jose|fast-jwt]  (default: both)
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
  ops_per_sec: number;
  mean_us: number;
  p50_us: number;
  p99_us: number;
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
const BATCHES = 5;
const BATCH_SIZE = 20_000;
const SAMPLES = 5_000;

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

async function runBatch(fn: VerifyFn, token: string, n: number, isAsync: boolean): Promise<number> {
  const t0 = Bun.nanoseconds();
  if (isAsync) {
    for (let i = 0; i < n; i++) await fn(token);
  } else {
    for (let i = 0; i < n; i++) fn(token);
  }
  return Bun.nanoseconds() - t0;
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
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

async function benchCase(impl: Impl, c: Fixture): Promise<Result> {
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

  let best = Infinity;
  for (let b = 0; b < BATCHES; b++) {
    best = Math.min(best, await runBatch(fn, token, BATCH_SIZE, impl.async));
  }
  const meanNs = best / BATCH_SIZE;

  const samples = new Array<number>(SAMPLES);
  if (impl.async) {
    for (let i = 0; i < SAMPLES; i++) {
      const t0 = Bun.nanoseconds();
      await fn(token);
      samples[i] = Bun.nanoseconds() - t0;
    }
  } else {
    for (let i = 0; i < SAMPLES; i++) {
      const t0 = Bun.nanoseconds();
      fn(token);
      samples[i] = Bun.nanoseconds() - t0;
    }
  }
  samples.sort((a, b) => a - b);

  return {
    impl: impl.label,
    name: c.name,
    token_len: c.token_len,
    key_len: Buffer.byteLength(c.key, "utf8"),
    ops_per_sec: Math.round(1e9 / meanNs),
    mean_us: +(meanNs / 1e3).toFixed(3),
    p50_us: +(percentile(samples, 50) / 1e3).toFixed(3),
    p99_us: +(percentile(samples, 99) / 1e3).toFixed(3),
  };
}

function printTable(rows: Result[]): void {
  const cols: (keyof Result)[] = ["impl", "name", "token_len", "key_len", "ops_per_sec", "mean_us", "p50_us", "p99_us"];
  const cells = rows.map((r) => cols.map((k) => (typeof r[k] === "number" ? r[k].toLocaleString("en-US") : String(r[k]))));
  const widths = cols.map((k, i) => Math.max(k.length, ...cells.map((row) => row[i]!.length)));
  const fmt = (row: string[]) =>
    row.map((v, i) => (i < 2 ? v.padEnd(widths[i]!) : v.padStart(widths[i]!))).join("  ");
  console.log(fmt(cols));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const row of cells) console.log(fmt(row));
  console.log();
}

const only = Bun.argv[2];
const selected = only === undefined ? impls : impls.filter((i) => i.id === only);
if (selected.length === 0) {
  throw new Error(`unknown impl ${only}; expected one of: ${impls.map((i) => i.id).join(", ")}`);
}

const fixtures = (await Bun.file(FIXTURES).json()) as Fixture[];
console.log(`Bun ${Bun.version}, ${fixtures.length} cases\n`);

for (const impl of selected) {
  const rows: Result[] = [];
  for (const c of fixtures) rows.push(await benchCase(impl, c));
  await Bun.write(join(RESULTS_DIR, `${impl.id}.json`), JSON.stringify(rows, null, 2) + "\n");
  printTable(rows);
}
