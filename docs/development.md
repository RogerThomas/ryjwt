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

For another Python, use its own venv: `UV_PROJECT_ENVIRONMENT=.venv-312 uv run --python 3.12 pytest`
(`.venv-313` for `3.13`, `.venv-314t` for `3.14t`).

CI runs the same tasks on each supported Python. The Python examples in these pages and the README
run as tests (`tests/test_docs.py`).

## Releases

Releases use [Release Please](https://github.com/googleapis/release-please), so commits to `main`
follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`,
`feat!: …` for a breaking change). On each push to `main`, the Release workflow
(`.github/workflows/release.yml`) keeps a release PR open. It bumps the version in `Cargo.toml`
(the package's version comes from it) and updates `CHANGELOG.md`.

Merging it tags the release. The same run builds the sdist and the wheels (cp312, cp313, cp314 and
cp314t, per platform), and tests each wheel on its own Python, in its own job. It publishes them
to PyPI, checking by SHA-256 that they're the files tested, then deploys this site to GitHub Pages.
