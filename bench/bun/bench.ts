// JWT verify benchmark for Bun: jose vs fast-jwt over bench/fixtures.json.
// Run from bench/bun:  bun run bench.ts
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

type VerifyFn = () => unknown;

interface Impl {
  id: string; // results file stem
  label: string; // "<lib> <version>"
  async: boolean;
  // Builds the per-case verify closure; all setup happens here, outside timing.
  prepare(c: Fixture): VerifyFn;
}

const WARMUP = 1_000;
const BATCHES = 5;
const BATCH_SIZE = 20_000;
const SAMPLES = 5_000;

const BENCH_DIR = join(import.meta.dir, "..");
const FIXTURES = join(BENCH_DIR, "fixtures.json");
const RESULTS_DIR = join(BENCH_DIR, "results");

const impls: Impl[] = [
  {
    id: "jose",
    label: `jose ${josePkg.version}`,
    async: true,
    prepare(c) {
      const secret = new TextEncoder().encode(c.key);
      const opts = { algorithms: [c.alg], audience: c.audience };
      return () => jwtVerify(c.token, secret, opts).then((r) => r.payload);
    },
  },
  {
    id: "fast-jwt",
    label: `fast-jwt ${fastJwtPkg.version}`,
    async: false,
    prepare(c) {
      const verify = createVerifier({
        key: c.key,
        // fixtures are all HS256; fast-jwt's Algorithm union is narrower than string
        algorithms: [c.alg as "HS256"],
        allowedAud: c.audience,
        cache: false,
      });
      return () => verify(c.token);
    },
  },
];

async function runBatch(fn: VerifyFn, n: number, isAsync: boolean): Promise<number> {
  const t0 = Bun.nanoseconds();
  if (isAsync) {
    for (let i = 0; i < n; i++) await fn();
  } else {
    for (let i = 0; i < n; i++) fn();
  }
  return Bun.nanoseconds() - t0;
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

async function benchCase(impl: Impl, c: Fixture): Promise<Result> {
  const fn = impl.prepare(c);

  // Correctness check.
  const decoded = await fn();
  if (!Bun.deepEquals(decoded, c.payload, true)) {
    throw new Error(`${impl.label} ${c.name}: decoded payload mismatch`);
  }

  await runBatch(fn, WARMUP, impl.async);

  let best = Infinity;
  for (let b = 0; b < BATCHES; b++) {
    best = Math.min(best, await runBatch(fn, BATCH_SIZE, impl.async));
  }
  const meanNs = best / BATCH_SIZE;

  const samples = new Array<number>(SAMPLES);
  if (impl.async) {
    for (let i = 0; i < SAMPLES; i++) {
      const t0 = Bun.nanoseconds();
      await fn();
      samples[i] = Bun.nanoseconds() - t0;
    }
  } else {
    for (let i = 0; i < SAMPLES; i++) {
      const t0 = Bun.nanoseconds();
      fn();
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

const fixtures = (await Bun.file(FIXTURES).json()) as Fixture[];
console.log(`Bun ${Bun.version}, ${fixtures.length} cases\n`);

for (const impl of impls) {
  const rows: Result[] = [];
  for (const c of fixtures) rows.push(await benchCase(impl, c));
  await Bun.write(join(RESULTS_DIR, `${impl.id}.json`), JSON.stringify(rows, null, 2) + "\n");
  printTable(rows);
}
