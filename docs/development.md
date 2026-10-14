# Development

ryjwt is a Rust extension ([PyO3](https://pyo3.rs/), built with [maturin](https://www.maturin.rs/))
with a thin Python layer. You need [uv](https://docs.astral.sh/uv/), [Task](https://taskfile.dev)
and rustup; `.python-version` and `rust-toolchain.toml` pin the versions.

| command | what it does |
| :-- | :-- |
| `task lint` | rustfmt, clippy and ruff, read-only (`task rustfmt` and `task ruff` fix what they can) |
| `task typecheck` | pyright on the package, then the tests (the public interface) under mypy, ty, pyright, zuban and pyrefly |
| `task test` | the tests, rebuilding the extension if the Rust changed |
| `task licenses` | regenerates `THIRD_PARTY_LICENSES` with [cargo-about](https://github.com/EmbarkStudios/cargo-about), after a `Cargo.lock` change |
| `task docs` | serves this site, rebuilding as you edit |
| `task docs-test` | builds the site strictly, failing on any warning, broken link or unresolved reference |
| `task fuzz` | fuzzes the Rust core (see [Fuzzing](#fuzzing)) |

For another Python, use its own venv: `UV_PROJECT_ENVIRONMENT=.venv-312 uv run --python 3.12 pytest`
(`.venv-313` for `3.13`, `.venv-314t` for `3.14t`).

CI runs the same tasks on each supported Python. The Python examples in these pages and the README
run as tests (`tests/test_docs.py`).

## Fuzzing

`task fuzz` runs coverage-guided fuzzing on the code that reads untrusted input, with
[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libFuzzer and AddressSanitizer).
It needs cargo-fuzz (`cargo install cargo-fuzz`), and nightly Rust, which it installs itself: a
dated nightly, pinned in `Taskfile.yml`, so a new one can't break it unannounced.

Each target embeds Python and calls ryjwt's public API, on a build of the extension instrumented
for the fuzzer. It checks what ryjwt does against references: Python's `json` and `hmac`, the
cryptography package, and ryjwt's own slower paths. The checks are in `fuzz/harness.py`.

| target | what it gives ryjwt |
| :-- | :-- |
| `decode` | tokens, to each kind of key, and to `unverified_token` |
| `claims` | payloads (and headers), signed, then decoded into dicts, Structs and models |
| `encode` | claims and header parameters of every kind, encoded, then decoded back |
| `jwks` | JWKS documents, to `PublicKey.from_jwks` and the JWKS client's reading |
| `keys` | key material, to `SecretKey`, `PrivateKey` and `PublicKey` |

`task fuzz` builds the targets (`task fuzz-build`), then runs each for `FUZZ_TIME` seconds (600 by
default); `task fuzz -- decode` runs one. The inputs found are kept in `fuzz/corpus/`, which
`fuzz/seeds.py` seeds from the bench's keys and tokens, and `task fuzz-cmin` trims to those that add
coverage. A crash, a sanitizer error or a failed check stops the run and saves the input in
`fuzz/artifacts/<target>/`; `task fuzz -- decode artifacts/decode/crash-…` (the path relative to
`fuzz/`) reruns it. The Fuzz workflow (`.github/workflows/fuzz.yml`) runs every target for five
minutes twice a week, and minimises its corpus. If one fails, its log shows only libFuzzer's summary
and seed, as the input may be an exploit and the logs are public. On the corpus that run started
from, `FUZZ_SEED=<seed> task fuzz -- <target>` finds it again.

A crash may be a vulnerability: report it privately, as the
[security policy](https://github.com/RogerThomas/ryjwt/blob/main/SECURITY.md) says.

## Releases

Releases use [Release Please](https://github.com/googleapis/release-please), so commits to `main`
follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`,
`feat!: …` for a breaking change). On each push to `main`, the Release workflow
(`.github/workflows/release.yml`) keeps a release PR open. It bumps the version in `Cargo.toml`
(the package's version comes from it) and updates `CHANGELOG.md`.

Merging it tags the release. The same run builds the sdist and the wheels (cp312 to cp315, cp314t
and cp315t, per platform), and tests each wheel on its own Python. It publishes them
to PyPI, checking by SHA-256 that they're the files tested, then deploys this site to GitHub Pages.
