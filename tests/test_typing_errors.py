"""What a user's type checker must reject: misuse of ryjwt's public API.

Each line of tests/typing_errors/ that ends in `# error` must be a type error under every checker
`task typecheck-public` runs (which excludes that directory), and no other line may be one.
"""

import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True, slots=True)
class Checker:
    command: list[str]
    error: re.Pattern[str]
    """Matches a line of the output reporting an error, capturing its `path` and `line`."""


@pytest.fixture(name="typing_errors")
def _typing_errors(pytestconfig: pytest.Config) -> list[Path]:
    return sorted((pytestconfig.rootpath / "tests" / "typing_errors").glob("*.py"))


def _checker(name: str, files: list[Path], rootpath: Path, tmp_path: Path) -> Checker:
    """Checker `name`, run on `files` with the project's configuration."""
    bin_dir = Path(sys.executable).parent
    paths = [str(file) for file in files]
    match name:
        case "mypy":
            return Checker(
                [str(bin_dir / "mypy"), *paths],
                re.compile(r"^(?P<path>\S+?\.py):(?P<line>\d+): error:", re.MULTILINE),
            )
        case "zuban":
            return Checker(
                [str(bin_dir / "zuban"), "check", *paths],
                re.compile(r"^(?P<path>\S+?\.py):(?P<line>\d+): error:", re.MULTILINE),
            )
        case "ty":
            return Checker(
                [str(bin_dir / "ty"), "check", "--output-format", "concise", *paths],
                re.compile(r"^(?P<path>\S+?\.py):(?P<line>\d+):\d+: error\[", re.MULTILINE),
            )
        case "pyrefly":
            return Checker(
                [str(bin_dir / "pyrefly"), "check", "--output-format", "min-text", *paths],
                re.compile(r"^ERROR (?P<path>\S+?\.py):(?P<line>\d+):", re.MULTILINE),
            )
        case _:
            # pyright skips excluded files even when they're named, so it gets the project's
            # settings without the `exclude`.
            pyproject = tomllib.loads((rootpath / "pyproject.toml").read_text())
            settings = {k: v for k, v in pyproject["tool"]["pyright"].items() if k != "exclude"}
            config = tmp_path / "pyrightconfig.json"
            config.write_text(json.dumps(settings))
            return Checker(
                [
                    str(bin_dir / "pyright"),
                    "--project",
                    str(config),
                    "--pythonpath",
                    sys.executable,
                    *paths,
                ],
                re.compile(r"^\s*(?P<path>\S+?\.py):(?P<line>\d+):\d+ - error:", re.MULTILINE),
            )


def _marked_lines(files: list[Path]) -> set[tuple[str, int]]:
    return {
        (file.name, number)
        for file in files
        for number, line in enumerate(file.read_text().splitlines(), start=1)
        if line.endswith("# error")
    }


@pytest.mark.timeout(120)
@pytest.mark.parametrize("name", ["mypy", "ty", "pyright", "zuban", "pyrefly"])
def test_checker_rejects_exactly_the_marked_lines(
    name: str,
    typing_errors: list[Path],
    pytestconfig: pytest.Config,
    tmp_path: Path,
) -> None:
    checker = _checker(name, typing_errors, pytestconfig.rootpath, tmp_path)

    result = subprocess.run(
        checker.command,
        cwd=pytestconfig.rootpath,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    reported = {
        (Path(match["path"]).name, int(match["line"]))
        for match in checker.error.finditer(result.stdout)
    }
    assert reported == _marked_lines(typing_errors), result.stdout + result.stderr
