// JWT verify benchmark for Bun over the full matrix (bench/matrix/fixtures.json): jose and
// fast-jwt, per algorithm, key size, payload size and key source. Mirrors bench/bench_matrix.py.
// Run from bench/bun:  bun run matrix.ts <jose|fast-jwt> [jwks_url] [only_sources] [only_cases] [budget]
//
// Key sources: "hmac" (the HS256 secret), "pem" (the public key's PEM, imported once), "jwks" (a
// JWKS document, the token's kid picks the key) and "jwks-url-async" (the document fetched over
// HTTPS, timed with the keys cached after a warm-up; the first fetch is timed on its own). JS has no
// sync JWKS URL client. The JWKS server's test CA comes from NODE_EXTRA_CA_CERTS.
import { createLocalJWKSet, createRemoteJWKSet, importSPKI, jwtVerify } from "jose";
import { createVerifier } from "fast-jwt";
import buildGetJwks from "get-jwks";
import { join } from "node:path";
import josePkg from "jose/package.json" with { type: "json" };
import fastJwtPkg from "fast-jwt/package.json" with { type: "json" };
import getJwksPkg from "get-jwks/package.json" with { type: "json" };

interface Key {
  alg: string;
  size: string;
  label: string;
  kid?: string;
  pem?: string;
  jwks?: string;
}

interface Fixture {
  name: string;
  key: string;
  alg: string;
  payload_size: string;
  secret?: string;
  token: string;
  token_len: number;
  audience: string;
  payload: Record<string, unknown>;
}

type Source = "hmac" | "pem" | "jwks" | "jwks-url-sync" | "jwks-url-async";
const SOURCES: Source[] = ["hmac", "pem", "jwks", "jwks-url-sync", "jwks-url-async"];

interface Row {
  impl: string;
  source: Source;
  name: string;
  key: string;
  alg: string;
  payload_size: string;
  token_len: number;
  iterations: number;
  ops_per_sec: number;
  mean_us: number;
  p50_us: number;
  p99_us: number;
}

interface NotApplicable {
  source: Source;
  alg: string; // "*" for every algorithm
  reason: string;
}

// One decode returning the payload; `isAsync` ones return a promise of it.
interface Prepared {
  verify: () => unknown;
  isAsync: boolean;
}

interface Impl {
  id: string; // results file stem
  label: string;
  notApplicable: NotApplicable[];
  notes: string[]; // how each source is done, for the results page
  // Builds the decode for a case and source; all setup happens here, outside timing.
  prepare(source: Source, c: Fixture, key: Key): Promise<Prepared>;
}

const [, , only = "jose", jwksUrlArg = "https://jwks:8443", onlySources = "", onlyCases = "", budgetArg = "1"] =
  Bun.argv;
const JWKS_URL = jwksUrlArg.replace(/\/$/, "");
const BUDGET = Number(budgetArg);
// Per-case time budgets (s): the warm-up estimates one call's cost, from which the batch and sample
// counts follow (capped as in bench.ts). The mean is the best batch's.
const WARMUP_S = 0.1 * BUDGET;
const BATCH_S = 0.2 * BUDGET;
const SAMPLES_S = 0.3 * BUDGET;
const REPEATS = 5;
const MAX_ITERATIONS = 20_000;
const MAX_SAMPLES = 5_000;
const MIN_COUNT = 10;
const FIRST_FETCH_CASE = "typical-rs3072";
const FIRST_FETCH_TRIALS = 5;

const BENCH_DIR = join(import.meta.dir, "..");
const FIXTURES = join(BENCH_DIR, "matrix", "fixtures.json");
const RESULTS_DIR = join(BENCH_DIR, "results", "matrix");

// Bun's fetch pools connections process-wide, so a fresh client would reuse the last one's; as
// PyJWT's urllib does, ask for a new connection per fetch, so first fetches include connect + TLS.
const FRESH_CONNECTION = { connection: "close" };
const jwksUrl = (c: Fixture) => `${JWKS_URL}/${c.key}.json`;
const sync = (verify: () => unknown): Prepared => ({ verify, isAsync: false });
const async_ = (verify: () => Promise<unknown>): Prepared => ({ verify, isAsync: true });

const impls: Impl[] = [
  {
    id: "jose",
    label: `jose ${josePkg.version}`,
    notApplicable: [{ source: "jwks-url-sync", alg: "*", reason: "jose's API is async only" }],
    notes: ["`importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`"],
    async prepare(source, c, key) {
      const opts = { algorithms: [c.alg], audience: c.audience };
      const verifyWith = (k: Parameters<typeof jwtVerify>[1]) => async_(() => jwtVerify(c.token, k, opts).then((r) => r.payload));
      switch (source) {
        case "hmac":
          return verifyWith(new TextEncoder().encode(c.secret));
        case "pem":
          return verifyWith(await importSPKI(key.pem!, c.alg));
        case "jwks": {
          const jwks = createLocalJWKSet(JSON.parse(key.jwks!));
          return async_(() => jwtVerify(c.token, jwks, opts).then((r) => r.payload));
        }
        default: {
          const jwks = createRemoteJWKSet(new URL(jwksUrl(c)), { headers: FRESH_CONNECTION });
          return async_(() => jwtVerify(c.token, jwks, opts).then((r) => r.payload));
        }
      }
    },
  },
  {
    id: "fast-jwt",
    label: `fast-jwt ${fastJwtPkg.version}`,
    notApplicable: [
      {
        source: "jwks",
        alg: "*",
        reason: "fast-jwt takes JWKS only from a URL (via get-jwks), not a document",
      },
      { source: "jwks-url-sync", alg: "*", reason: "fast-jwt's JWKS support (get-jwks) is async only" },
      {
        source: "jwks-url-async",
        alg: "EdDSA",
        reason: "get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys",
      },
    ],
    notes: [
      `JWKS URL via get-jwks ${getJwksPkg.version} (fast-jwt's documented integration): it converts the` +
        " cached JWK to a PEM, which fast-jwt parses, on every verify",
    ],
    async prepare(source, c, key) {
      // fast-jwt's Algorithm union is narrower than string; the fixtures only hold valid names
      const algorithms = [c.alg as "HS256"];
      const opts = { algorithms, allowedAud: c.audience, cache: false };
      switch (source) {
        case "hmac": {
          const verify = createVerifier({ ...opts, key: c.secret! });
          return sync(() => verify(c.token));
        }
        case "pem": {
          const verify = createVerifier({ ...opts, key: key.pem! });
          return sync(() => verify(c.token));
        }
        default: {
          // fast-jwt's documented JWKS integration: get-jwks fetches (and caches) the JWKS, and
          // hands fast-jwt the token's key as a PEM.
          const getJwks = buildGetJwks({ jwksPath: `${c.key}.json`, fetchOptions: { headers: FRESH_CONNECTION } });
          const verify = createVerifier({
            ...opts,
            key: async ({ header }: { header: Record<string, string> }) => getJwks.getPublicKey({ domain: JWKS_URL, alg: header.alg, kid: header.kid }),
          });
          return async_(() => verify(c.token));
        }
      }
    },
  },
];

async function call(p: Prepared): Promise<unknown> {
  return p.isAsync ? await p.verify() : p.verify();
}

async function batch(p: Prepared, n: number): Promise<number> {
  const { verify } = p;
  const t0 = Bun.nanoseconds();
  if (p.isAsync) {
    for (let i = 0; i < n; i++) await verify();
  } else {
    for (let i = 0; i < n; i++) verify();
  }
  return Bun.nanoseconds() - t0;
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

const clamp = (n: number, max: number) => Math.max(MIN_COUNT, Math.min(max, Math.floor(n)));

async function benchCase(impl: Impl, source: Source, c: Fixture, key: Key): Promise<Row> {
  const p = await impl.prepare(source, c, key);
  const decoded = await call(p);
  if (!Bun.deepEquals(decoded, c.payload, true)) {
    throw new Error(`${impl.label} ${source} ${c.name}: decoded payload mismatch`);
  }

  const start = Bun.nanoseconds();
  const deadline = start + WARMUP_S * 1e9;
  let calls = 0;
  while (calls < MIN_COUNT || Bun.nanoseconds() < deadline) {
    await call(p);
    calls++;
  }
  const perCall = (Bun.nanoseconds() - start) / calls;
  const iterations = clamp((BATCH_S * 1e9) / perCall, MAX_ITERATIONS);
  const nSamples = clamp((SAMPLES_S * 1e9) / perCall, MAX_SAMPLES);

  let best = Infinity;
  for (let b = 0; b < REPEATS; b++) best = Math.min(best, await batch(p, iterations));
  const meanNs = best / iterations;

  const samples = new Array<number>(nSamples);
  for (let i = 0; i < nSamples; i++) {
    const t0 = Bun.nanoseconds();
    if (p.isAsync) await p.verify();
    else p.verify();
    samples[i] = Bun.nanoseconds() - t0;
  }
  samples.sort((a, b) => a - b);

  return {
    impl: impl.label,
    source,
    name: c.name,
    key: c.key,
    alg: c.alg,
    payload_size: c.payload_size,
    token_len: c.token_len,
    iterations,
    ops_per_sec: Math.round(1e9 / meanNs),
    mean_us: +(meanNs / 1e3).toFixed(3),
    p50_us: +(percentile(samples, 50) / 1e3).toFixed(3),
    p99_us: +(percentile(samples, 99) / 1e3).toFixed(3),
  };
}

// Milliseconds to the first decode of a fresh client, per trial.
async function firstFetch(impl: Impl, source: Source, c: Fixture, key: Key): Promise<number[]> {
  const trials: number[] = [];
  for (let i = 0; i < FIRST_FETCH_TRIALS; i++) {
    const p = await impl.prepare(source, c, key);
    const t0 = Bun.nanoseconds();
    const decoded = await call(p);
    trials.push((Bun.nanoseconds() - t0) / 1e6);
    if (!Bun.deepEquals(decoded, c.payload, true)) {
      throw new Error(`${impl.label} ${source} ${c.name}: decoded payload mismatch`);
    }
  }
  return trials;
}

function printTable(rows: Row[]): void {
  const cols: (keyof Row)[] = ["source", "name", "token_len", "iterations", "ops_per_sec", "mean_us", "p50_us", "p99_us"];
  const cells = rows.map((r) => cols.map((k) => (typeof r[k] === "number" ? r[k].toLocaleString("en-US") : String(r[k]))));
  const widths = cols.map((k, i) => Math.max(k.length, ...cells.map((row) => row[i]!.length)));
  const fmt = (row: string[]) =>
    row.map((v, i) => (i < 2 ? v.padEnd(widths[i]!) : v.padStart(widths[i]!))).join("  ");
  console.log(fmt(cols));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const row of cells) console.log(fmt(row));
  console.log();
}

const impl = impls.find((i) => i.id === only);
if (impl === undefined) {
  throw new Error(`unknown impl ${only}; expected one of: ${impls.map((i) => i.id).join(", ")}`);
}

const { keys, cases } = (await Bun.file(FIXTURES).json()) as { keys: Record<string, Key>; cases: Fixture[] };
const skipped = new Set(impl.notApplicable.filter((n) => n.alg === "*").map((n) => n.source));
const requested = onlySources ? (onlySources.split(",") as Source[]) : SOURCES;
const selected = requested.filter((s) => !skipped.has(s));
const selectedCases = cases.filter((c) => !onlyCases || onlyCases.split(",").includes(c.name));
console.log(`${impl.label} on Bun ${Bun.version}, ${selectedCases.length} cases x ${selected.join(", ")}\n`);

const rows: Row[] = [];
const firstFetches: { source: Source; name: string; ms: number; trials_ms: number[] }[] = [];
for (const source of selected) {
  const sourceRows: Row[] = [];
  for (const c of selectedCases) {
    if ((c.alg === "HS256") !== (source === "hmac")) continue;
    if (impl.notApplicable.some((n) => n.source === source && n.alg === c.alg)) continue;
    if (source.startsWith("jwks-url") && c.name === FIRST_FETCH_CASE) {
      const trials = await firstFetch(impl, source, c, keys[c.key]!);
      const ms = [...trials].sort((a, b) => a - b)[Math.floor(trials.length / 2)]!;
      firstFetches.push({ source, name: c.name, ms, trials_ms: trials });
    }
    sourceRows.push(await benchCase(impl, source, c, keys[c.key]!));
  }
  printTable(sourceRows);
  rows.push(...sourceRows);
}
for (const f of firstFetches) {
  console.log(`first fetch, ${f.source} (${f.name}): median ${f.ms.toFixed(2)} ms [${f.trials_ms.map((t) => t.toFixed(1)).join(", ")}]`);
}

const out = join(RESULTS_DIR, `${impl.id}.json`);
const results = {
  impl: impl.label,
  runtime: `Bun ${Bun.version}`,
  rows,
  first_fetch: firstFetches,
  not_applicable: impl.notApplicable,
  notes: impl.notes,
};
await Bun.write(out, JSON.stringify(results, null, 2) + "\n");
console.log(`wrote ${out}`);
