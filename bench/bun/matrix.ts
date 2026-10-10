// JWT verify benchmark for Bun over the full matrix (bench/matrix/fixtures.json): jose and
// fast-jwt, per algorithm, key size, payload size and key source. Mirrors bench/bench_matrix.py.
// Run from bench/bun:  bun run matrix.ts <jose|fast-jwt> [jwks_url] [only_sources] [only_cases] [iterations] [rounds]
// (an empty filter means all; iterations: decodes per timed round, default 10000; rounds default 1).
// Each case: 1,000 untimed warm-up decodes, then `rounds` timed loops of `iterations` decodes; the
// mean is over every timed decode.
//
// Key sources: "hmac" (the HS256 secret), "pem" (the public key's PEM, imported once), "jwks" (a
// JWKS document, the token's kid picks the key) and "jwks-url-async" (the document fetched over
// HTTPS, timed with the keys cached after a warm-up; the first fetch is timed on its own). JS has no
// sync JWKS URL client. The JWKS server's test CA comes from NODE_EXTRA_CA_CERTS.
import { createLocalJWKSet, createRemoteJWKSet, importSPKI, jwtVerify } from "jose";
import { createDecoder, createVerifier } from "fast-jwt";
import buildGetJwks from "get-jwks";
import { createPublicKey, type webcrypto } from "node:crypto";
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
  expired_token: string; // exp a minute after iat, long past
  wrong_audience_token: string; // aud is another audience
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
  rounds: number;
  ops_per_sec: number;
  mean_us: number;
  round_means_us: number[];
}

interface NotApplicable {
  source: Source;
  alg: string; // "*" for every algorithm
  reason: string;
}

// Decodes a token, returning its payload; `isAsync` ones return a promise of it.
interface Prepared {
  verify: (token: string) => unknown;
  isAsync: boolean;
}

// The fields (e.g. `code`) the error a rejection throws must carry.
type ExpectedError = Record<string, string>;

interface Impl {
  id: string; // results file stem
  label: string;
  notApplicable: NotApplicable[];
  notes: string[]; // how each source is done, for the results page
  // What each prepared decode must throw for the case's expired and wrong-audience tokens.
  rejects: { expired: ExpectedError; wrongAudience: ExpectedError };
  // Builds the decode for a case and source; all setup happens here, outside timing.
  prepare(source: Source, c: Fixture, key: Key): Promise<Prepared>;
}

const [
  ,
  ,
  only = "jose",
  jwksUrlArg = "https://jwks:8443",
  onlySources = "",
  onlyCases = "",
  iterationsArg = "10000",
  roundsArg = "1",
] = Bun.argv;
const JWKS_URL = jwksUrlArg.replace(/\/$/, "");
const ITERATIONS = Number(iterationsArg);
const ROUNDS = Number(roundsArg);
for (const [what, n] of [["iterations", ITERATIONS], ["rounds", ROUNDS]] as const) {
  if (!Number.isInteger(n) || n < 1) throw new Error(`${what} must be a positive integer, got ${n}`);
}
const WARMUP = 1_000;
const FIRST_FETCH_CASE = "typical-rs3072";
const FIRST_FETCH_TRIALS = 5;

const BENCH_DIR = join(import.meta.dir, "..");
const FIXTURES = join(BENCH_DIR, "matrix", "fixtures.json");
const RESULTS_DIR = join(BENCH_DIR, "results", "matrix");

// Bun's fetch pools connections process-wide, so a fresh client would reuse the last one's; as
// PyJWT's urllib does, ask for a new connection per fetch, so first fetches include connect + TLS.
const FRESH_CONNECTION = { connection: "close" };
const jwksUrl = (c: Fixture) => `${JWKS_URL}/${c.key}.json`;
const sync = (verify: (token: string) => unknown): Prepared => ({ verify, isAsync: false });
const async_ = (verify: (token: string) => Promise<unknown>): Prepared => ({ verify, isAsync: true });

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
    notApplicable: [{ source: "jwks-url-sync", alg: "*", reason: "jose's API is async only" }],
    notes: ["HMAC secret imported once (`crypto.subtle.importKey`); `importSPKI`, `createLocalJWKSet`, `createRemoteJWKSet`"],
    rejects: {
      expired: { code: "ERR_JWT_EXPIRED" },
      wrongAudience: { code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "aud" },
    },
    async prepare(source, c, key) {
      const opts = { algorithms: [c.alg], audience: c.audience };
      const verifyWith = (k: Parameters<typeof jwtVerify>[1]) => async_((token) => jwtVerify(token, k, opts).then((r) => r.payload));
      switch (source) {
        case "hmac":
          return verifyWith(await hmacKey(c.secret!, c.alg));
        case "pem":
          return verifyWith(await importSPKI(key.pem!, c.alg));
        case "jwks":
          return verifyWith(createLocalJWKSet(JSON.parse(key.jwks!)));
        default:
          return verifyWith(createRemoteJWKSet(new URL(jwksUrl(c)), { headers: FRESH_CONNECTION }));
      }
    },
  },
  {
    id: "fast-jwt",
    label: `fast-jwt ${fastJwtPkg.version}`,
    notApplicable: [
      { source: "jwks-url-sync", alg: "*", reason: "fast-jwt's JWKS support (get-jwks) is async only" },
      {
        source: "jwks-url-async",
        alg: "EdDSA",
        reason: "get-jwks converts JWKs with jwk-to-pem, which doesn't support OKP (Ed25519) keys",
      },
    ],
    notes: [
      "JWKS document: a verifier per key, made once, picked by the token's `kid` (read with `createDecoder`)",
      `JWKS URL rows are fast-jwt + get-jwks ${getJwksPkg.version} (fast-jwt's documented integration), so they` +
        " time both: on every verify get-jwks converts the cached JWK to a PEM (with jwk-to-pem) and fast-jwt" +
        " imports that PEM (`createPublicKey`), which is why they're slow",
    ],
    rejects: {
      expired: { code: "FAST_JWT_EXPIRED" },
      wrongAudience: { code: "FAST_JWT_INVALID_CLAIM_VALUE" },
    },
    async prepare(source, c, key) {
      // fast-jwt's Algorithm union is narrower than string; the fixtures only hold valid names
      const algorithms = [c.alg as "HS256"];
      const opts = { algorithms, allowedAud: c.audience, cache: false };
      switch (source) {
        case "hmac": {
          const verify = createVerifier({ ...opts, key: c.secret! });
          return sync((token) => verify(token));
        }
        case "pem": {
          const verify = createVerifier({ ...opts, key: key.pem! });
          return sync((token) => verify(token));
        }
        case "jwks": {
          // fast-jwt has no JWKS document support: make a verifier per key once (its JWK converted
          // to a PEM once), and pick one by the token's kid, read with fast-jwt's own decoder.
          const decode = createDecoder({ complete: true });
          const verifiers = new Map<string, (token: string) => unknown>();
          for (const jwk of (JSON.parse(key.jwks!) as { keys: (webcrypto.JsonWebKey & { kid: string })[] }).keys) {
            const pem = createPublicKey({ key: jwk, format: "jwk" }).export({ type: "spki", format: "pem" }) as string;
            verifiers.set(jwk.kid, createVerifier({ ...opts, key: pem }));
          }
          return sync((token) => {
            const kid = String(decode(token).header.kid);
            const verify = verifiers.get(kid);
            if (verify === undefined) throw new Error(`no key with kid ${kid}`);
            return verify(token);
          });
        }
        default: {
          // fast-jwt's documented JWKS integration: get-jwks fetches (and caches) the JWKS, and
          // hands fast-jwt the token's key as a PEM.
          const getJwks = buildGetJwks({ jwksPath: `${c.key}.json`, fetchOptions: { headers: FRESH_CONNECTION } });
          const verify = createVerifier({
            ...opts,
            key: async ({ header }: { header: Record<string, string> }) => getJwks.getPublicKey({ domain: JWKS_URL, alg: header.alg, kid: header.kid }),
          });
          return async_((token) => verify(token));
        }
      }
    },
  },
];

async function call(p: Prepared, token: string): Promise<unknown> {
  return p.isAsync ? await p.verify(token) : p.verify(token);
}

// Nanoseconds for `n` decodes of `token`, in one loop.
async function batch(p: Prepared, token: string, n: number): Promise<number> {
  const { verify } = p;
  const t0 = Bun.nanoseconds();
  if (p.isAsync) {
    for (let i = 0; i < n; i++) await verify(token);
  } else {
    for (let i = 0; i < n; i++) verify(token);
  }
  return Bun.nanoseconds() - t0;
}

// Throws unless `p` rejects `token` with an error carrying every field of `expected`.
async function checkRejects(p: Prepared, token: string, expected: ExpectedError, where: string, what: string): Promise<void> {
  let error: unknown;
  try {
    await call(p, token);
  } catch (e) {
    error = e;
  }
  if (error === undefined) throw new Error(`${where}: accepted ${what}`);
  const fields = error as Record<string, unknown>;
  if (!Object.entries(expected).every(([k, v]) => fields[k] === v)) {
    throw new Error(`${where}: rejected ${what} with the wrong error (wanted ${JSON.stringify(expected)}): ${error}`);
  }
}

async function benchCase(impl: Impl, source: Source, c: Fixture, key: Key): Promise<Row> {
  const p = await impl.prepare(source, c, key);
  const token = c.token;
  const where = `${impl.label} ${source} ${c.name}`;
  // Before timing: decodes the token, and rejects an expired one and another audience's.
  const decoded = await call(p, token);
  if (!Bun.deepEquals(decoded, c.payload, true)) {
    throw new Error(`${where}: decoded payload mismatch`);
  }
  await checkRejects(p, c.expired_token, impl.rejects.expired, where, "an expired token");
  await checkRejects(p, c.wrong_audience_token, impl.rejects.wrongAudience, where, "another audience's token");

  await batch(p, token, WARMUP);

  const roundNs: number[] = [];
  for (let r = 0; r < ROUNDS; r++) roundNs.push(await batch(p, token, ITERATIONS));
  const meanNs = roundNs.reduce((a, b) => a + b, 0) / (ITERATIONS * ROUNDS);

  return {
    impl: impl.label,
    source,
    name: c.name,
    key: c.key,
    alg: c.alg,
    payload_size: c.payload_size,
    token_len: c.token_len,
    iterations: ITERATIONS,
    rounds: ROUNDS,
    ops_per_sec: Math.round(1e9 / meanNs),
    mean_us: +(meanNs / 1e3).toFixed(3),
    round_means_us: roundNs.map((ns) => +(ns / ITERATIONS / 1e3).toFixed(3)),
  };
}

// Milliseconds to the first decode of a fresh client, per trial.
async function firstFetch(impl: Impl, source: Source, c: Fixture, key: Key): Promise<number[]> {
  const trials: number[] = [];
  for (let i = 0; i < FIRST_FETCH_TRIALS; i++) {
    const p = await impl.prepare(source, c, key);
    const t0 = Bun.nanoseconds();
    const decoded = await call(p, c.token);
    trials.push((Bun.nanoseconds() - t0) / 1e6);
    if (!Bun.deepEquals(decoded, c.payload, true)) {
      throw new Error(`${impl.label} ${source} ${c.name}: decoded payload mismatch`);
    }
  }
  return trials;
}

// The min–max of a row's round means, e.g. "1.234–1.301".
function roundSpread(r: Row): string {
  return `${Math.min(...r.round_means_us).toFixed(3)}–${Math.max(...r.round_means_us).toFixed(3)}`;
}

function printTable(rows: Row[]): void {
  const cols: (keyof Row)[] = ["source", "name", "token_len", "iterations", "rounds", "mean_us"];
  const headers: string[] = [...cols];
  const cells = rows.map((r) => cols.map((k) => (typeof r[k] === "number" ? r[k].toLocaleString("en-US") : String(r[k]))));
  if (ROUNDS > 1) {
    headers.push("round_means_us");
    rows.forEach((r, i) => cells[i]!.push(roundSpread(r)));
  }
  const widths = headers.map((k, i) => Math.max(k.length, ...cells.map((row) => row[i]!.length)));
  const fmt = (row: string[]) =>
    row.map((v, i) => (i < 2 ? v.padEnd(widths[i]!) : v.padStart(widths[i]!))).join("  ");
  console.log(fmt(headers));
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
