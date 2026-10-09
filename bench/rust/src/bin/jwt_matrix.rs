//! Benchmark `jsonwebtoken::decode` (aws-lc-rs backend) over the full matrix in
//! `bench/matrix/fixtures.json`, per algorithm, key size, payload size and key source. Mirrors
//! `bench/bench_matrix.py`: each case's iteration counts follow from its cost, measured in the
//! warm-up, so slow cases run fewer iterations in about the same time.
//!
//! Key sources: `hmac` (the HS256 secret), `pem` (the public key's PEM) and `jwks` (a JWKS document:
//! `JwkSet`, each key turned into a `DecodingKey` with `DecodingKey::from_jwk` once, then picked per
//! token by the `kid` from `decode_header`). jsonwebtoken doesn't fetch JWKS URLs.
//!
//! Usage: `jwt_matrix [budget] [only_sources] [only_cases]`: `budget` scales each case's time (1.0:
//! 0.1 s warm-up, 5 batches of 0.2 s, 0.3 s of samples); `only_sources` and `only_cases` are
//! comma-separated filters, as bench_matrix.py's (empty: all).

use std::collections::HashMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Serialize;
use serde_json::Value;

const REPEATS: u32 = 5;
const MAX_ITERATIONS: u64 = 20_000;
const MAX_SAMPLES: u64 = 5_000;
const MIN_COUNT: u64 = 10;

#[derive(Serialize)]
struct Row {
    #[serde(rename = "impl")]
    impl_name: String,
    source: &'static str,
    name: String,
    key: String,
    alg: String,
    payload_size: String,
    token_len: u64,
    iterations: u64,
    ops_per_sec: f64,
    mean_us: f64,
    p50_us: f64,
    p99_us: f64,
}

#[derive(Serialize)]
struct NotApplicable {
    source: &'static str,
    alg: &'static str, // "*" for every algorithm
    reason: &'static str,
}

#[derive(Serialize)]
struct Results {
    #[serde(rename = "impl")]
    impl_name: String,
    runtime: String,
    rows: Vec<Row>,
    first_fetch: Vec<Value>,
    not_applicable: Vec<NotApplicable>,
    notes: Vec<&'static str>,
}

struct Budget {
    warmup: Duration,
    batch: Duration,
    samples: Duration,
}

struct Stats {
    iterations: u64,
    mean_ns: f64,
    p50_ns: f64,
    p99_ns: f64,
}

fn bench_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `jsonwebtoken` version as resolved in Cargo.lock (embedded at compile time).
fn jsonwebtoken_version() -> &'static str {
    let lock = include_str!("../../Cargo.lock");
    let rest = lock
        .split("name = \"jsonwebtoken\"\nversion = \"")
        .nth(1)
        .expect("jsonwebtoken in Cargo.lock");
    &rest[..rest.find('"').expect("closing quote")]
}

/// Python `statistics.median` on sorted data.
fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        f64::midpoint(sorted[n / 2 - 1], sorted[n / 2])
    }
}

/// Python `statistics.quantiles(data, n=100, method="inclusive")[98]` on sorted data.
fn p99_inclusive(sorted: &[f64]) -> f64 {
    let m = sorted.len() - 1;
    let i = 99 * m;
    let (j, delta) = (i / 100, (i % 100) as f64);
    (sorted[j] * (100.0 - delta) + sorted[j + 1] * delta) / 100.0
}

/// Runs the methodology against `call`, which must perform one decode.
fn measure(budget: &Budget, mut call: impl FnMut()) -> Stats {
    let start = Instant::now();
    let mut calls = 0u64;
    while calls < MIN_COUNT || start.elapsed() < budget.warmup {
        call();
        calls += 1;
    }
    let per_call_ns = start.elapsed().as_nanos() as f64 / calls as f64;
    let count =
        |d: Duration, max: u64| ((d.as_nanos() as f64 / per_call_ns) as u64).clamp(MIN_COUNT, max);
    let iterations = count(budget.batch, MAX_ITERATIONS);
    let best_ns = (0..REPEATS)
        .map(|_| {
            let t0 = Instant::now();
            for _ in 0..iterations {
                call();
            }
            t0.elapsed().as_nanos()
        })
        .min()
        .expect("REPEATS > 0");
    let mut samples: Vec<f64> = (0..count(budget.samples, MAX_SAMPLES))
        .map(|_| {
            let t0 = Instant::now();
            call();
            t0.elapsed().as_nanos() as f64
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    Stats {
        iterations,
        mean_ns: best_ns as f64 / iterations as f64,
        p50_ns: median(&samples),
        p99_ns: p99_inclusive(&samples),
    }
}

fn pem_key(alg: Algorithm, pem: &str) -> DecodingKey {
    let key = match alg {
        Algorithm::RS256 => DecodingKey::from_rsa_pem(pem.as_bytes()),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pem.as_bytes()),
        _ => DecodingKey::from_ec_pem(pem.as_bytes()),
    };
    key.expect("PEM key")
}

/// Each key of a JWKS document as a `DecodingKey`, by `kid`.
fn jwks_keys(jwks: &str) -> HashMap<String, DecodingKey> {
    let set: JwkSet = serde_json::from_str(jwks).expect("parse JWKS");
    set.keys
        .iter()
        .map(|jwk| {
            let kid = jwk.common.key_id.clone().expect("kid");
            (kid, DecodingKey::from_jwk(jwk).expect("JWK"))
        })
        .collect()
}

/// The comma-separated filter at argument `n`: `None` (everything) if it's missing or empty.
fn filter_arg(n: usize) -> Option<Vec<String>> {
    let arg = std::env::args().nth(n).filter(|s| !s.is_empty())?;
    Some(arg.split(',').map(str::to_owned).collect())
}

/// Whether `filter` (from `filter_arg`) takes `name`.
fn selected(filter: Option<&Vec<String>>, name: &str) -> bool {
    filter.is_none_or(|names| names.iter().any(|n| n == name))
}

fn main() {
    let budget_scale: f64 = std::env::args()
        .nth(1)
        .map_or(1.0, |s| s.parse().expect("budget"));
    let only_sources = filter_arg(2);
    let only_cases = filter_arg(3);
    let budget = Budget {
        warmup: Duration::from_secs_f64(0.1 * budget_scale),
        batch: Duration::from_secs_f64(0.2 * budget_scale),
        samples: Duration::from_secs_f64(0.3 * budget_scale),
    };
    let impl_name = format!("jsonwebtoken {} (aws-lc-rs)", jsonwebtoken_version());
    let raw = std::fs::read_to_string(bench_dir().join("matrix").join("fixtures.json"))
        .expect("read matrix/fixtures.json");
    let fixtures: Value = serde_json::from_str(&raw).expect("parse matrix/fixtures.json");
    let not_applicable = vec![
        NotApplicable {
            source: "*",
            alg: "ES512",
            reason: "jsonwebtoken has no ES512 (P-521)",
        },
        NotApplicable {
            source: "jwks-url-sync",
            alg: "*",
            reason: "jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache)",
        },
        NotApplicable {
            source: "jwks-url-async",
            alg: "*",
            reason: "jsonwebtoken doesn't fetch JWKS URLs (it takes your own HTTP client and cache)",
        },
    ];
    println!("{impl_name}");

    let mut rows = Vec::new();
    for source in ["hmac", "pem", "jwks"] {
        if !selected(only_sources.as_ref(), source) {
            continue;
        }
        println!(
            "\n{source}\n{:<16} {:>9} {:>10} {:>10} {:>9} {:>9}",
            "case", "token_len", "iterations", "mean µs", "p50 µs", "p99 µs"
        );
        for case in fixtures["cases"].as_array().expect("cases") {
            let s = |k: &str| case[k].as_str().expect(k).to_owned();
            let (name, alg_name, token) = (s("name"), s("alg"), s("token"));
            if (alg_name == "HS256") != (source == "hmac")
                || alg_name == "ES512"
                || !selected(only_cases.as_ref(), &name)
            {
                continue;
            }
            let key = &fixtures["keys"][s("key")];
            let alg: Algorithm = alg_name.parse().expect("algorithm");
            let mut validation = Validation::new(alg);
            validation.set_audience(&[s("audience")]);
            assert!(validation.validate_exp, "exp must be validated");

            let stats = match source {
                "hmac" => {
                    let key = DecodingKey::from_secret(s("secret").as_bytes());
                    let decoded = decode::<Value>(&token, &key, &validation).expect("decode");
                    assert_eq!(decoded.claims, case["payload"], "{name}: payload mismatch");
                    measure(&budget, || {
                        black_box(
                            decode::<Value>(black_box(&token), &key, &validation).expect("decode"),
                        );
                    })
                }
                "pem" => {
                    let key = pem_key(alg, key["pem"].as_str().expect("pem"));
                    let decoded = decode::<Value>(&token, &key, &validation).expect("decode");
                    assert_eq!(decoded.claims, case["payload"], "{name}: payload mismatch");
                    measure(&budget, || {
                        black_box(
                            decode::<Value>(black_box(&token), &key, &validation).expect("decode"),
                        );
                    })
                }
                _ => {
                    let keys = jwks_keys(key["jwks"].as_str().expect("jwks"));
                    let verify = |token: &str| {
                        let kid = decode_header(token).expect("header").kid.expect("kid");
                        decode::<Value>(token, &keys[&kid], &validation).expect("decode")
                    };
                    assert_eq!(
                        verify(&token).claims,
                        case["payload"],
                        "{name}: payload mismatch"
                    );
                    measure(&budget, || {
                        black_box(verify(black_box(&token)));
                    })
                }
            };
            println!(
                "{name:<16} {:>9} {:>10} {:>10.3} {:>9.3} {:>9.3}",
                token.len(),
                stats.iterations,
                stats.mean_ns / 1e3,
                stats.p50_ns / 1e3,
                stats.p99_ns / 1e3
            );
            rows.push(Row {
                impl_name: impl_name.clone(),
                source,
                name,
                key: s("key"),
                alg: alg_name,
                payload_size: s("payload_size"),
                token_len: case["token_len"].as_u64().expect("token_len"),
                iterations: stats.iterations,
                ops_per_sec: 1e9 / stats.mean_ns,
                mean_us: stats.mean_ns / 1e3,
                p50_us: stats.p50_ns / 1e3,
                p99_us: stats.p99_ns / 1e3,
            });
        }
    }

    let results = Results {
        impl_name,
        runtime: "Rust (release, LTO)".to_owned(),
        rows,
        first_fetch: Vec::new(),
        not_applicable,
        notes: vec![
            "JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`)",
        ],
    };
    let out = bench_dir()
        .join("results")
        .join("matrix")
        .join("jsonwebtoken.json");
    std::fs::create_dir_all(out.parent().expect("parent")).expect("mkdir results/matrix");
    let body = serde_json::to_string_pretty(&results).expect("serialize") + "\n";
    std::fs::write(&out, body).expect("write results");
    println!("\nwrote {}", out.canonicalize().unwrap_or(out).display());
}
