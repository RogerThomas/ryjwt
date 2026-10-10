//! Benchmark `jsonwebtoken::decode` (aws-lc-rs backend) over the full matrix in
//! `bench/matrix/fixtures.json`, per algorithm, key size, payload size and key source. Mirrors
//! `bench/bench_matrix.py`: 1,000 untimed warm-up decodes, then `rounds` rounds of `iterations`
//! decodes, each round timed as one loop.
//!
//! Key sources: `hmac` (the HS256 secret), `pem` (the public key's PEM) and `jwks` (a JWKS document:
//! `JwkSet`, each key turned into a `DecodingKey` with `DecodingKey::from_jwk` once, then picked per
//! token by the `kid` from `decode_header`). jsonwebtoken doesn't fetch JWKS URLs.
//!
//! Usage: `jwt_matrix <value|struct> [only_sources] [only_cases] [iterations] [rounds]`: `value`
//! decodes into `serde_json::Value` and writes `results/matrix/jsonwebtoken.json`; `struct` decodes
//! into typed claims structs, the same fields ryjwt's msgspec lane decodes, and writes
//! `results/matrix/jsonwebtoken-struct.json`. `only_sources` and `only_cases` are comma-separated
//! filters, as bench_matrix.py's (empty: all); `iterations` (default 10,000) and `rounds` (default
//! 1) as there.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ITERATIONS: u64 = 10_000;
const ROUNDS: u64 = 1;
const WARMUP: u64 = 1_000;

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
    rounds: u64,
    ops_per_sec: f64,
    mean_us: f64,
    round_means_us: Vec<f64>,
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

/// What the claims decode into: `serde_json::Value`, or the typed structs below.
#[derive(Clone, Copy)]
enum Mode {
    Value,
    Struct,
}

impl Mode {
    fn from_arg(arg: Option<&str>) -> Self {
        match arg {
            Some("value") => Self::Value,
            Some("struct") => Self::Struct,
            other => panic!(
                "usage: jwt_matrix <value|struct> [only_sources] [only_cases] [iterations] \
                 [rounds] (got {other:?})"
            ),
        }
    }

    /// Ends the impl label: `jsonwebtoken <ver> (aws-lc-rs) → <target>`.
    fn target(self) -> &'static str {
        match self {
            Self::Value => "Value",
            Self::Struct => "struct",
        }
    }

    fn results_file(self) -> &'static str {
        match self {
            Self::Value => "jsonwebtoken.json",
            Self::Struct => "jsonwebtoken-struct.json",
        }
    }
}

/// The claims of the non-"typical" payloads, as `BaseClaimsStruct` in `bench_python.py`. Other
/// claims in the payload (`claim_0`, ...) are ignored.
#[derive(Deserialize, PartialEq, Debug)]
struct BaseClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
}

/// The claims of the "typical" payloads, as `TypicalClaimsStruct` in `bench_python.py`.
#[derive(Deserialize, PartialEq, Debug)]
struct TypicalClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    nbf: i64,
    jti: String,
    sid: String,
    email: String,
    name: String,
    scope: String,
    roles: Vec<String>,
    amr: Vec<String>,
}

/// What a decode can produce: `Value` or one of the claims structs.
trait Claims: DeserializeOwned + PartialEq + Debug {}

impl<T: DeserializeOwned + PartialEq + Debug> Claims for T {}

/// Where a case's `DecodingKey` comes from.
enum KeySource<'a> {
    Secret(&'a str),
    Pem(Algorithm, &'a str),
    Jwks(&'a str),
}

/// A case's token and what its decode is checked against before it's timed.
struct Checks<'a> {
    label: &'a str,
    token: &'a str,
    payload: &'a Value,
    expired_token: &'a str,
    wrong_audience_token: &'a str,
}

#[derive(Clone, Copy)]
struct Timing {
    iterations: u64,
    rounds: u64,
}

struct Stats {
    mean_us: f64,
    round_means_us: Vec<f64>,
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

/// Runs the methodology against `call`, which must perform one decode: `WARMUP` untimed calls,
/// then `timing.rounds` rounds of `timing.iterations` calls, the clock read once per round.
fn measure(timing: Timing, mut call: impl FnMut()) -> Stats {
    for _ in 0..WARMUP {
        call();
    }
    let round_ns: Vec<u128> = (0..timing.rounds)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..timing.iterations {
                call();
            }
            start.elapsed().as_nanos()
        })
        .collect();

    let per_round = timing.iterations as f64;
    let total_ns = round_ns.iter().sum::<u128>() as f64;
    Stats {
        mean_us: total_ns / (per_round * timing.rounds as f64) / 1e3,
        round_means_us: round_ns
            .iter()
            .map(|&ns| ns as f64 / per_round / 1e3)
            .collect(),
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

/// Panics unless `verify` rejects `expired_token` as expired and `wrong_audience_token` as for
/// another audience, so the timed decode is known to check both. `label` starts each message.
fn assert_rejects<T>(
    label: &str,
    expired_token: &str,
    wrong_audience_token: &str,
    verify: impl Fn(&str) -> Result<TokenData<T>, Error>,
) {
    for (token, expected, what) in [
        (
            expired_token,
            ErrorKind::ExpiredSignature,
            "an expired token",
        ),
        (
            wrong_audience_token,
            ErrorKind::InvalidAudience,
            "another audience's token",
        ),
    ] {
        match verify(token) {
            Ok(_) => panic!("{label}: accepted {what}"),
            Err(e) if *e.kind() == expected => {}
            Err(e) => panic!(
                "{label}: rejected {what} with {:?}, not {expected:?}",
                e.kind()
            ),
        }
    }
}

/// Checks `verify` on the case (the claims it decodes must equal the fixture payload read as `T`,
/// and it must reject the expired and other-audience tokens), then times it on the case's token.
fn check_and_measure<T: Claims>(
    checks: &Checks,
    timing: Timing,
    verify: impl Fn(&str) -> Result<TokenData<T>, Error>,
) -> Stats {
    let label = checks.label;
    let expected: T = serde_json::from_value(checks.payload.clone())
        .unwrap_or_else(|e| panic!("{label}: fixture payload as claims: {e}"));
    let decoded = verify(checks.token).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"));
    assert_eq!(decoded.claims, expected, "{label}: payload mismatch");
    assert_rejects(
        label,
        checks.expired_token,
        checks.wrong_audience_token,
        &verify,
    );
    measure(timing, || {
        black_box(verify(black_box(checks.token)).expect("decode"));
    })
}

/// Builds the case's key from `source` (once, outside the timed loop), then checks and times
/// decoding into `T` with it.
fn bench_source<T: Claims>(
    source: &KeySource,
    validation: &Validation,
    checks: &Checks,
    timing: Timing,
) -> Stats {
    match *source {
        KeySource::Secret(secret) => {
            let key = DecodingKey::from_secret(secret.as_bytes());
            check_and_measure(checks, timing, |t| decode::<T>(t, &key, validation))
        }
        KeySource::Pem(alg, pem) => {
            let key = pem_key(alg, pem);
            check_and_measure(checks, timing, |t| decode::<T>(t, &key, validation))
        }
        KeySource::Jwks(jwks) => {
            let keys = jwks_keys(jwks);
            check_and_measure(checks, timing, |t| {
                let kid = decode_header(t).expect("header").kid.expect("kid");
                decode::<T>(t, &keys[&kid], validation)
            })
        }
    }
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
    let args: Vec<String> = std::env::args().collect();
    let mode = Mode::from_arg(args.get(1).map(String::as_str));
    let only_sources = filter_arg(2);
    let only_cases = filter_arg(3);
    let timing = Timing {
        iterations: args
            .get(4)
            .map_or(ITERATIONS, |s| s.parse().expect("iterations")),
        rounds: args.get(5).map_or(ROUNDS, |s| s.parse().expect("rounds")),
    };
    let impl_name = format!(
        "jsonwebtoken {} (aws-lc-rs) → {}",
        jsonwebtoken_version(),
        mode.target()
    );
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
    println!(
        "{impl_name} — {WARMUP} warm-up, then {} rounds of {} iters",
        timing.rounds, timing.iterations
    );

    let mut rows = Vec::new();
    for source in ["hmac", "pem", "jwks"] {
        if !selected(only_sources.as_ref(), source) {
            continue;
        }
        print!(
            "\n{source}\n{:<16} {:>9} {:>10} {:>6} {:>10}",
            "case", "token_len", "iterations", "rounds", "mean µs"
        );
        if timing.rounds > 1 {
            print!(" {:>17}", "round means µs");
        }
        println!();
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
            // ryjwt checks nbf, with no leeway, by default; so do the Python libraries.
            validation.validate_nbf = true;
            validation.leeway = 0;
            assert!(validation.validate_exp, "exp must be validated");
            let key_source = match source {
                "hmac" => KeySource::Secret(case["secret"].as_str().expect("secret")),
                "pem" => KeySource::Pem(alg, key["pem"].as_str().expect("pem")),
                _ => KeySource::Jwks(key["jwks"].as_str().expect("jwks")),
            };
            // Each source must also reject an expired token and one for another audience.
            let label = format!("{impl_name} {source} {name}");
            let checks = Checks {
                label: &label,
                token: &token,
                payload: &case["payload"],
                expired_token: case["expired_token"].as_str().expect("expired_token"),
                wrong_audience_token: case["wrong_audience_token"]
                    .as_str()
                    .expect("wrong_audience_token"),
            };
            let payload_size = s("payload_size");

            // As bench_matrix.py: the "typical" payloads decode into their own, larger struct.
            let stats = match (mode, payload_size == "typical") {
                (Mode::Value, _) => {
                    bench_source::<Value>(&key_source, &validation, &checks, timing)
                }
                (Mode::Struct, false) => {
                    bench_source::<BaseClaims>(&key_source, &validation, &checks, timing)
                }
                (Mode::Struct, true) => {
                    bench_source::<TypicalClaims>(&key_source, &validation, &checks, timing)
                }
            };
            print!(
                "{name:<16} {:>9} {:>10} {:>6} {:>10.3}",
                token.len(),
                timing.iterations,
                timing.rounds,
                stats.mean_us
            );
            if timing.rounds > 1 {
                let min = stats
                    .round_means_us
                    .iter()
                    .copied()
                    .fold(f64::INFINITY, f64::min);
                let max = stats.round_means_us.iter().copied().fold(0.0, f64::max);
                print!(" {:>17}", format!("{min:.3}–{max:.3}"));
            }
            println!();
            rows.push(Row {
                impl_name: impl_name.clone(),
                source,
                name,
                key: s("key"),
                alg: alg_name,
                payload_size,
                token_len: case["token_len"].as_u64().expect("token_len"),
                iterations: timing.iterations,
                rounds: timing.rounds,
                ops_per_sec: 1e6 / stats.mean_us,
                mean_us: stats.mean_us,
                round_means_us: stats.round_means_us,
            });
        }
    }

    let mut notes = vec![
        "JWKS: each key turned into a `DecodingKey` once, picked per token by `kid` (`decode_header`)",
    ];
    if let Mode::Struct = mode {
        notes.push(
            "claims decoded into typed structs with the fields ryjwt's msgspec lane decodes; other claims ignored",
        );
    }
    let results = Results {
        impl_name,
        runtime: "Rust (release, LTO)".to_owned(),
        rows,
        first_fetch: Vec::new(),
        not_applicable,
        notes,
    };
    let out = bench_dir()
        .join("results")
        .join("matrix")
        .join(mode.results_file());
    std::fs::create_dir_all(out.parent().expect("parent")).expect("mkdir results/matrix");
    let body = serde_json::to_string_pretty(&results).expect("serialize") + "\n";
    std::fs::write(&out, body).expect("write results");
    println!("\nwrote {}", out.canonicalize().unwrap_or(out).display());
}
