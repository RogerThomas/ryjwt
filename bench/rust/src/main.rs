//! Benchmark `jsonwebtoken::decode` (HS256 verify + exp/aud validation, aws-lc-rs backend)
//! over the shared fixture matrix. Mirrors `bench/bench_pyjwt.py` methodology.

use std::fmt::Write as _;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Serialize;
use serde_json::Value;

const ITERATIONS: u32 = 20_000;
const WARMUP: u32 = 1_000;
const REPEATS: u32 = 5;
const SAMPLES: usize = 5_000;

struct Case {
    name: String,
    key: String,
    token: String,
    token_len: u64,
    audience: String,
    payload: Value,
}

/// One output row; field order matches `results/pyjwt.json`.
#[derive(Serialize)]
struct Row<'a> {
    #[serde(rename = "impl")]
    impl_name: &'a str,
    name: &'a str,
    token_len: u64,
    key_len: usize,
    ops_per_sec: f64,
    mean_us: f64,
    p50_us: f64,
    p99_us: f64,
}

struct Stats {
    ops_per_sec: f64,
    mean_us: f64,
    p50_us: f64,
    p99_us: f64,
}

fn bench_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `jsonwebtoken` version as resolved in Cargo.lock (embedded at compile time).
fn jsonwebtoken_version() -> &'static str {
    let lock = include_str!("../Cargo.lock");
    let rest = lock
        .split("name = \"jsonwebtoken\"\nversion = \"")
        .nth(1)
        .expect("jsonwebtoken in Cargo.lock");
    &rest[..rest.find('"').expect("closing quote")]
}

fn load_cases() -> Vec<Case> {
    let raw =
        std::fs::read_to_string(bench_dir().join("fixtures.json")).expect("read fixtures.json");
    let cases: Vec<Value> = serde_json::from_str(&raw).expect("parse fixtures.json");
    cases
        .into_iter()
        .map(|c| {
            assert_eq!(c["alg"], "HS256", "only HS256 fixtures are supported");
            let s = |k: &str| c[k].as_str().expect(k).to_owned();
            Case {
                name: s("name"),
                key: s("key"),
                token: s("token"),
                token_len: c["token_len"].as_u64().expect("token_len"),
                audience: s("audience"),
                payload: c["payload"].clone(),
            }
        })
        .collect()
}

/// Python `statistics.median` on sorted data.
fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// Python `statistics.quantiles(data, n=100, method="inclusive")[98]` on sorted data.
fn p99_inclusive(sorted: &[f64]) -> f64 {
    let m = sorted.len() - 1;
    let i = 99 * m;
    let (j, delta) = (i / 100, (i % 100) as f64);
    (sorted[j] * (100.0 - delta) + sorted[j + 1] * delta) / 100.0
}

/// Runs the full methodology against `call`, which must perform one decode.
fn measure(mut call: impl FnMut()) -> Stats {
    for _ in 0..WARMUP {
        call();
    }
    let best_ns = (0..REPEATS)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                call();
            }
            start.elapsed().as_nanos()
        })
        .min()
        .expect("REPEATS > 0");

    let mut samples: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let t0 = Instant::now();
            call();
            t0.elapsed().as_nanos() as f64
        })
        .collect();
    samples.sort_by(f64::total_cmp);

    let mean_ns = best_ns as f64 / f64::from(ITERATIONS);
    Stats {
        ops_per_sec: 1e9 / mean_ns,
        mean_us: mean_ns / 1e3,
        p50_us: median(&samples) / 1e3,
        p99_us: p99_inclusive(&samples) / 1e3,
    }
}

fn row(name: &str, token_len: u64, key_len: usize, s: &Stats) -> String {
    format!(
        "{name:<14} {token_len:>9} {key_len:>7} {:>12.0} {:>9.3} {:>9.3} {:>9.3}",
        s.ops_per_sec, s.mean_us, s.p50_us, s.p99_us
    )
}

fn header() -> String {
    format!(
        "{:<14} {:>9} {:>7} {:>12} {:>9} {:>9} {:>9}",
        "case", "token_len", "key_len", "ops/s", "mean µs", "p50 µs", "p99 µs"
    )
}

fn main() {
    let impl_name = format!("jsonwebtoken {} (aws-lc-rs)", jsonwebtoken_version());
    let cases = load_cases();
    println!(
        "{impl_name} — {ITERATIONS} iters x {REPEATS} repeats (best), {SAMPLES} timed samples"
    );

    let mut results = Vec::with_capacity(cases.len());
    let mut headline = String::new();
    let mut inloop = String::new();

    for case in &cases {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[&case.audience]);
        assert!(validation.validate_exp, "exp must be validated");
        let key_bytes = case.key.as_bytes();
        let key = DecodingKey::from_secret(key_bytes);

        // Correctness: decoded claims must equal the fixture payload.
        let decoded = decode::<Value>(&case.token, &key, &validation)
            .unwrap_or_else(|e| panic!("{}: decode failed: {e}", case.name));
        assert_eq!(
            decoded.claims, case.payload,
            "{}: payload mismatch",
            case.name
        );

        // Headline: key + validation built once, outside the timed loop.
        let s = measure(|| {
            let r = decode::<Value>(
                black_box(case.token.as_str()),
                black_box(&key),
                black_box(&validation),
            );
            black_box(r.expect("decode"));
        });
        writeln!(
            headline,
            "{}",
            row(&case.name, case.token_len, key_bytes.len(), &s)
        )
        .expect("fmt");

        // Variant: DecodingKey built inside the loop, to isolate key-setup cost.
        let s2 = measure(|| {
            let k = DecodingKey::from_secret(black_box(key_bytes));
            let r = decode::<Value>(black_box(case.token.as_str()), &k, black_box(&validation));
            black_box(r.expect("decode"));
        });
        writeln!(
            inloop,
            "{}",
            row(&case.name, case.token_len, key_bytes.len(), &s2)
        )
        .expect("fmt");

        results.push(Row {
            impl_name: &impl_name,
            name: &case.name,
            token_len: case.token_len,
            key_len: key_bytes.len(),
            ops_per_sec: s.ops_per_sec,
            mean_us: s.mean_us,
            p50_us: s.p50_us,
            p99_us: s.p99_us,
        });
    }

    let out = bench_dir().join("results").join("jsonwebtoken.json");
    std::fs::create_dir_all(out.parent().expect("parent")).expect("mkdir results");
    let body = serde_json::to_string_pretty(&results).expect("serialize") + "\n";
    std::fs::write(&out, body).expect("write results");

    println!("\ndecode::<Value> — {impl_name} (DecodingKey pre-built)");
    println!("{}\n{headline}", header());
    println!("variant: DecodingKey::from_secret inside the loop (not written to JSON)");
    println!("{}\n{inloop}", header());
    println!("wrote {}", out.canonicalize().unwrap_or(out).display());
}
