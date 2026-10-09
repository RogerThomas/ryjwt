# Development

ryjwt is a Rust extension ([PyO3](https://pyo3.rs/), built with [maturin](https://www.maturin.rs/))
with a thin Python layer. You need [uv](https://docs.astral.sh/uv/), [Task](https://taskfile.dev)
and rustup; the Python and Rust versions come from `.python-version` and `rust-toolchain.toml`.

- `task lint`: rustfmt, clippy and ruff, without changing files (`task rustfmt` and `task ruff`
  fix what they can).
- `task typecheck`: pyright on the package, then the public interface (the tests) under five type
  checkers: mypy, ty, pyright, zuban and pyrefly.
- `task test`: the test suite, building the extension first if the Rust sources changed. For
  another Python, use a venv of its own:
  `UV_PROJECT_ENVIRONMENT=.venv-312 uv run --python 3.12 pytest` (and `.venv-313` with `3.13`,
  `.venv-314t` with `3.14t`).
- `task licenses`: regenerate `THIRD_PARTY_LICENSES` (with
  [cargo-about](https://github.com/EmbarkStudios/cargo-about)) after a `Cargo.lock` change.
- `task docs`: serve this site locally, rebuilding it as you edit; `task docs-test` builds it in
  strict mode, failing on any warning, broken link or unresolved reference.

CI runs the same tasks, testing on each supported Python. The Python examples in these pages, and
in the README, run as tests too (`tests/test_docs.py`).

## Releases

Releases use [Release Please](https://github.com/googleapis/release-please), so commits to `main`
follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat: …`, `fix: …`,
`feat!: …` for a breaking change). On every push to `main`, the Release workflow
(`.github/workflows/release.yml`) keeps a release PR open that bumps the version in `Cargo.toml`
(the package's version comes from it: `0.0.0-alpha.0` is `0.0.0a0`) and updates `CHANGELOG.md`.

Merging that PR tags the release, and the same workflow run builds the wheels (cp312, cp313, cp314
and cp314t, for each platform) and the sdist, tests each wheel on its own Python, in jobs of their
own, then publishes them to PyPI, checking by SHA-256 that they're the very files tested. Once
they're published, it builds this site and deploys it to GitHub Pages.
