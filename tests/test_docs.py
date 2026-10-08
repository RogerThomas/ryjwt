"""Runs every Python example in the docs (docs/**/*.md) and README.md, so an example can't rot.

Each ```python block runs on its own, in a fresh namespace. A block with a top-level `await` runs
with `asyncio.run`. An HTML comment on the line just before a block changes how it runs:

- `<!-- test: skip, <reason> -->`: the block isn't run, e.g. because it needs a real JWKS URL.
- `<!-- test: with-key-files -->`: the block runs in a temporary directory holding `private.pem`
  and `public.pem` (an ES256 key pair, PKCS#8 and SubjectPublicKeyInfo), `jwks.json` (a JWKS of
  that public key, with the `kid` `key-1`) and `secret.txt` (a 32-byte HMAC secret, then a
  newline).

Also checks that the API reference documents every public name, that the race SVGs the docs show
are the ones the README shows, and that the docs' favicon is assets/favicon.svg. The docs aren't in
the sdist: without docs/, those tests (and the docs' examples) are skipped; README.md's examples
still run.
"""

import ast
import asyncio
import inspect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Any, ClassVar, Self

import pytest
import ryjwt
from _support import make_jwk, private_pem, public_pem
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True, slots=True)
class Example:
    """A ```python block in a Markdown file."""

    path: Path
    line: int
    """The line of the block's first line of code."""
    code: str
    directive: str
    """What the `<!-- test: ... -->` comment before the block says, if anything."""

    def compiled(self) -> CodeType:
        """The block compiled, its line numbers those of the Markdown file, top-level `await`
        allowed."""
        source = "\n" * (self.line - 1) + self.code
        return compile(source, str(self.path), "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)


@dataclass(frozen=True, slots=True)
class Markdown:
    """The Markdown files whose examples run: README.md, and docs/**/*.md if docs/ is here."""

    root: Path
    docs: Path

    fence: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<indent>[ \t]*)```python[^\n]*\n(?P<code>.*?)^(?P=indent)```[ \t]*$",
        re.MULTILINE | re.DOTALL,
    )
    directive: ClassVar[re.Pattern[str]] = re.compile(r"<!--\s*test:\s*(?P<directive>.*?)\s*-->")

    def _directive(self, before: str) -> str:
        """What the `<!-- test: ... -->` comment on the line before a block says, if any."""
        previous = before.rstrip("\n").rpartition("\n")[2]
        match = self.directive.fullmatch(previous.strip())
        return match.group("directive") if match else ""

    def _examples(self, path: Path) -> list[Example]:
        text = path.read_text(encoding="utf-8")
        examples: list[Example] = []
        for match in self.fence.finditer(text):
            indent = len(match.group("indent"))
            code = "".join(line[indent:] for line in match.group("code").splitlines(keepends=True))
            line = text.count("\n", 0, match.start("code")) + 1
            directive = self._directive(text[: match.start()])
            examples.append(Example(path, line, code, directive))
        return examples

    def _files(self) -> list[Path]:
        pages = sorted(self.docs.rglob("*.md")) if self.docs.is_dir() else []
        return [self.root / "README.md", *pages]

    @classmethod
    def at(cls, root: Path) -> Self:
        return cls(root, root / "docs")

    def params(self) -> list[Any]:
        """A `pytest.param` per example, and a skipped one for the docs if they aren't here."""
        params: list[Any] = [
            pytest.param(example, id=f"{example.path.relative_to(self.root)}:{example.line}")
            for path in self._files()
            for example in self._examples(path)
        ]
        if not self.docs.is_dir():
            reason = "docs/ isn't here (e.g. in an sdist)"
            params.append(pytest.param(None, id="docs", marks=pytest.mark.skip(reason=reason)))
        return params


def _run(example: Example) -> dict[str, Any]:
    """Runs `example` in a fresh namespace, and returns it; with `asyncio.run` if it awaits at the
    top level."""
    namespace: dict[str, Any] = {"__name__": "__docs__"}
    result = eval(example.compiled(), namespace)
    if inspect.iscoroutine(result):
        asyncio.run(result)
    return namespace


def _write_key_files(directory: Path) -> None:
    """The files `<!-- test: with-key-files -->` examples use (see the module's docstring)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    (directory / "private.pem").write_bytes(private_pem(private_key))
    (directory / "public.pem").write_bytes(public_pem(private_key))
    jwks = {"keys": [make_jwk(private_key, kid="key-1", alg="ES256", use="sig")]}
    (directory / "jwks.json").write_text(json.dumps(jwks))
    (directory / "secret.txt").write_text("s" * 32 + "\n")


@pytest.fixture(name="markdown", scope="session")
def _markdown(pytestconfig: pytest.Config) -> Markdown:
    return Markdown.at(pytestconfig.rootpath)


@pytest.mark.parametrize("example", Markdown.at(Path(__file__).resolve().parents[1]).params())
def test_example_runs(
    example: Example,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if example.directive.startswith("skip"):
        pytest.skip(example.directive)
    if example.directive == "with-key-files":
        _write_key_files(tmp_path)
        monkeypatch.chdir(tmp_path)
    else:
        assert not example.directive, f"Unknown directive: <!-- test: {example.directive} -->"

    _run(example)


def test_an_example_may_await(tmp_path: Path) -> None:
    code = "import asyncio\n\nawait asyncio.sleep(0)\nawaited = True\n"

    namespace = _run(Example(tmp_path / "page.md", 1, code, ""))

    assert namespace["awaited"] is True


def test_api_reference_documents_every_public_name(markdown: Markdown) -> None:
    reference = markdown.docs / "reference.md"
    if not reference.is_file():
        pytest.skip("docs/ isn't here (e.g. in an sdist)")

    documented = re.findall(r"^::: ryjwt\.(\w+)$", reference.read_text(), re.MULTILINE)

    assert sorted(documented) == sorted(ryjwt.__all__)


def test_docs_show_the_readmes_race_svgs(markdown: Markdown) -> None:
    assets, docs_assets = markdown.root / "assets", markdown.docs / "assets"
    if not (assets.is_dir() and docs_assets.is_dir()):
        pytest.skip("assets/ or docs/assets/ isn't here (e.g. in an sdist)")
    svgs = sorted(path.name for path in assets.glob("perf-race*.svg"))

    assert svgs
    assert sorted(path.name for path in docs_assets.glob("perf-race*.svg")) == svgs
    for name in svgs:
        assert (docs_assets / name).read_bytes() == (assets / name).read_bytes(), (
            f"docs/assets/{name} differs from assets/{name}: run task race-svg"
        )


@pytest.mark.parametrize("name", ["favicon.svg", "logo-light.svg", "logo-dark.svg"])
def test_docs_logos_are_the_repos(name: str, markdown: Markdown) -> None:
    assets, docs_assets = markdown.root / "assets", markdown.docs / "assets"
    if not (assets.is_dir() and docs_assets.is_dir()):
        pytest.skip("assets/ or docs/assets/ isn't here (e.g. in an sdist)")

    assert (docs_assets / name).read_bytes() == (assets / name).read_bytes(), (
        f"docs/assets/{name} differs from assets/{name}: run task icons"
    )
