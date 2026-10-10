//! Benchmark `jsonwebtoken::decode` (HS256 verify + exp/aud validation, aws-lc-rs backend)
//! over the shared fixture matrix. Mirrors `bench/bench_python.py` methodology: 1,000 untimed
//! warm-up decodes, then `rounds` rounds of `iterations` decodes, each round timed as one loop.
//!
//! Usage: `jwt_bench <value|struct> [iterations] [rounds]` (defaults 10,000 and 1). `value`
//! decodes into `serde_json::Value` and writes `results/jsonwebtoken.json`; `struct` decodes into
//! typed claims structs, the same fields ryjwt's msgspec lane decodes, and writes
//! `results/jsonwebtoken-struct.json`.

use std::fmt::Debug;
use std::fmt::Write as _;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ITERATIONS: u32 = 10_000;
const ROUNDS: u32 = 1;
const WARMUP: u32 = 1_000;

struct Case {
    name: String,
    key: String,
    token: String,
    token_len: u64,
    audience: String,
    payload: Value,
    expired_token: String,
    wrong_audience_token: String,
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
            other => {
                panic!("usage: jwt_bench <value|struct> [iterations] [rounds] (got {other:?})")
            }
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

#[derive(Clone, Copy)]
struct Timing {
    iterations: u32,
    rounds: u32,
}

/// One output row; field order matches `results/pyjwt.json`.
#[derive(Serialize)]
struct Row<'a> {
    #[serde(rename = "impl")]
    impl_name: &'a str,
    name: &'a str,
    token_len: u64,
    key_len: usize,
    iterations: u32,
    rounds: u32,
    ops_per_sec: f64,
    mean_us: f64,
    round_means_us: Vec<f64>,
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
                expired_token: s("expired_token"),
                wrong_audience_token: s("wrong_audience_token"),
            }
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

    let per_round = f64::from(timing.iterations);
    let total_ns = round_ns.iter().sum::<u128>() as f64;
    Stats {
        mean_us: total_ns / (per_round * f64::from(timing.rounds)) / 1e3,
        round_means_us: round_ns
            .iter()
            .map(|&ns| ns as f64 / per_round / 1e3)
            .collect(),
    }
}

/// Checks `decode::<T>` on `case` (the claims must equal the fixture payload read as `T`, and
/// the expired and other-audience tokens must be rejected), then times it twice: with the
/// `DecodingKey` built once (the headline), and built inside the loop (the variant).
fn bench_case<T: Claims>(
    label: &str,
    case: &Case,
    validation: &Validation,
    timing: Timing,
) -> (Stats, Stats) {
    let key_bytes = case.key.as_bytes();
    let key = DecodingKey::from_secret(key_bytes);

    // Correctness: decoded claims must equal the fixture payload.
    let expected: T = serde_json::from_value(case.payload.clone())
        .unwrap_or_else(|e| panic!("{label}: fixture payload as claims: {e}"));
    let decoded = decode::<T>(&case.token, &key, validation)
        .unwrap_or_else(|e| panic!("{label}: decode failed: {e}"));
    assert_eq!(decoded.claims, expected, "{label}: payload mismatch");
    // And it must reject an expired token and one for another audience.
    assert_rejects(
        label,
        &case.expired_token,
        &case.wrong_audience_token,
        |token| decode::<T>(token, &key, validation),
    );

    // Headline: key + validation built once, outside the timed loop.
    let headline = measure(timing, || {
        let r = decode::<T>(
            black_box(case.token.as_str()),
            black_box(&key),
            black_box(validation),
        );
        black_box(r.expect("decode"));
    });

    // Variant: DecodingKey built inside the loop, to isolate key-setup cost.
    let inloop = measure(timing, || {
        let k = DecodingKey::from_secret(black_box(key_bytes));
        let r = decode::<T>(black_box(case.token.as_str()), &k, black_box(validation));
        black_box(r.expect("decode"));
    });
    (headline, inloop)
}

fn row(name: &str, token_len: u64, timing: Timing, s: &Stats) -> String {
    let mut line = format!(
        "{name:<14} {token_len:>9} {:>10} {:>6} {:>9.3}",
        timing.iterations, timing.rounds, s.mean_us
    );
    if timing.rounds > 1 {
        let min = s
            .round_means_us
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        let max = s.round_means_us.iter().copied().fold(0.0, f64::max);
        write!(line, " {:>17}", format!("{min:.3}–{max:.3}")).expect("fmt");
    }
    line
}

fn header(timing: Timing) -> String {
    let mut line = format!(
        "{:<14} {:>9} {:>10} {:>6} {:>9}",
        "case", "token_len", "iterations", "rounds", "mean µs"
    );
    if timing.rounds > 1 {
        write!(line, " {:>17}", "round means µs").expect("fmt");
    }
    line
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = Mode::from_arg(args.get(1).map(String::as_str));
    let timing = Timing {
        iterations: args
            .get(2)
            .map_or(ITERATIONS, |s| s.parse().expect("iterations")),
        rounds: args.get(3).map_or(ROUNDS, |s| s.parse().expect("rounds")),
    };
    let impl_name = format!(
        "jsonwebtoken {} (aws-lc-rs) → {}",
        jsonwebtoken_version(),
        mode.target()
    );
    let cases = load_cases();
    println!(
        "{impl_name} — {WARMUP} warm-up, then {} rounds of {} iters",
        timing.rounds, timing.iterations
    );

    let mut results = Vec::with_capacity(cases.len());
    let mut headline = String::new();
    let mut inloop = String::new();

    for case in &cases {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[&case.audience]);
        // ryjwt checks nbf, with no leeway, by default; so do the Python libraries.
        validation.validate_nbf = true;
        validation.leeway = 0;
        assert!(validation.validate_exp, "exp must be validated");

        let label = format!("{impl_name} {}", case.name);
        // As bench_python.py: the "typical" payloads decode into their own, larger struct.
        let (s, s2) = match (mode, case.name.starts_with("typical")) {
            (Mode::Value, _) => bench_case::<Value>(&label, case, &validation, timing),
            (Mode::Struct, false) => bench_case::<BaseClaims>(&label, case, &validation, timing),
            (Mode::Struct, true) => bench_case::<TypicalClaims>(&label, case, &validation, timing),
        };
        writeln!(headline, "{}", row(&case.name, case.token_len, timing, &s)).expect("fmt");
        writeln!(inloop, "{}", row(&case.name, case.token_len, timing, &s2)).expect("fmt");

        results.push(Row {
            impl_name: &impl_name,
            name: &case.name,
            token_len: case.token_len,
            key_len: case.key.len(),
            iterations: timing.iterations,
            rounds: timing.rounds,
            ops_per_sec: 1e6 / s.mean_us,
            mean_us: s.mean_us,
            round_means_us: s.round_means_us,
        });
    }

    let out = bench_dir().join("results").join(mode.results_file());
    std::fs::create_dir_all(out.parent().expect("parent")).expect("mkdir results");
    let body = serde_json::to_string_pretty(&results).expect("serialize") + "\n";
    std::fs::write(&out, body).expect("write results");

    println!("\n{impl_name} (DecodingKey pre-built)");
    println!("{}\n{headline}", header(timing));
    println!("variant: DecodingKey::from_secret inside the loop (not written to JSON)");
    println!("{}\n{inloop}", header(timing));
    println!("wrote {}", out.canonicalize().unwrap_or(out).display());
}
