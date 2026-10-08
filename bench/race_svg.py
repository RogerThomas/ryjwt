#!yeet
"""Draw the decode races, animated SVGs of how long each library takes to decode 100,000 tokens,
from the full matrix's results (bench/results-matrix/*.json): `task race-svg`. Each is written to
assets/ (which the README shows) and docs/assets/ (which the docs site shows).

- assets/perf-race.svg: HS256, a typical token, the 64-byte secret.
- assets/perf-race-es256.svg: ES256 with a PEM public key, a typical token. ES256 because Docker on
  Apple Silicon doesn't slow it down (see the Apple Silicon caveat in compare.py), so it's fair to
  every library.

A lane per library. Each bar fills over the time the library takes (decodes x its mean time per
decode), in real time, then every bar holds while the finish times show, and the race restarts.

The animation is pure CSS `@keyframes`, no JavaScript, so it plays where GitHub (and PyPI) show the
SVG as an image. Every `@keyframes` rule repeats its final value at 100%: without that stop, a
browser fills it in from the element's own attribute (`width="0"`, `opacity="0"`), and animates
back to it for the rest of the loop, so the bars would drain away instead of holding.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from rich.console import Console


@dataclass(frozen=True, slots=True)
class Lane:
    """One library's lane: what it's called, its colour, and its mean time per decode."""

    key: str
    """The results file's name (`ryjwt-msgspec`), for element ids."""
    name: str
    color: str
    mean_us: float
    version: str
    """The library as its results name it, version included (`fast-jwt 6.3.3`)."""


@dataclass(frozen=True, slots=True)
class Race:
    """One race: which case of the matrix, and how to describe it."""

    source: str
    case: str
    algorithm: str
    key: str
    """The key the tokens were verified with, for the caption."""
    output: str
    """The SVG's file name, in assets/."""


@dataclass(frozen=True, slots=True)
class RaceSVG:
    """An animated race of `lanes`, each decoding `decodes` tokens."""

    race: Race
    lanes: list[Lane]  # fastest first
    decodes: int
    token_bytes: int

    width: ClassVar[int] = 780
    lane_height: ClassVar[int] = 36
    lane_gap: ClassVar[int] = 6
    track_x: ClassVar[int] = 210
    track_width: ClassVar[int] = 470
    header_height: ClassVar[int] = 58
    hold_seconds: ClassVar[float] = 3.0
    axis_ticks: ClassVar[int] = 6

    def _title(self) -> str:
        return f"Decoding {self.decodes:,} {self.race.algorithm} tokens"

    def _setup(self) -> str:
        """What was decoded."""
        return (
            f"{self.race.algorithm} with {self.race.key}, a typical {self.token_bytes}-byte token"
        )

    def _seconds(self, lane: Lane) -> float:
        return self.decodes * lane.mean_us / 1e6

    def _race_seconds(self) -> float:
        return self._seconds(self.lanes[-1])

    def _loop_seconds(self) -> float:
        return self._race_seconds() + self.hold_seconds

    def _lane_y(self, index: int) -> int:
        return self.header_height + index * (self.lane_height + self.lane_gap)

    def _axis_bottom(self) -> int:
        return self._lane_y(len(self.lanes)) - self.lane_gap

    def _lane_style(self, lane: Lane) -> str:
        """The lane's animations: the bar fills, then its finish time shows, and both hold."""
        loop = self._loop_seconds()
        finish = self._seconds(lane) / loop * 100
        key = lane.key
        return (
            f"    #bar-{key} {{ animation: fill-{key} {loop:.3f}s linear infinite; }}\n"
            f"    #badge-{key} {{ animation: show-{key} {loop:.3f}s step-end infinite; }}\n"
            f"    @keyframes fill-{key} {{ 0% {{ width: 0; }} {finish:.3f}% "
            f"{{ width: {self.track_width}px; }} 100% {{ width: {self.track_width}px; }} }}\n"
            f"    @keyframes show-{key} {{ 0% {{ opacity: 0; }} {finish:.3f}% {{ opacity: 1; }} "
            f"100% {{ opacity: 1; }} }}"
        )

    def _lane(self, index: int, lane: Lane) -> str:
        y = self._lane_y(index)
        middle = y + self.lane_height / 2
        rate = 1e6 / lane.mean_us
        badge_x = self.track_x + self.track_width + 10
        return f"""  <g>
    <rect x="{self.track_x}" y="{y}" width="{self.track_width}" height="26" rx="4" class="track" />
    <rect id="bar-{lane.key}" x="{self.track_x}" y="{y}" width="0" height="26" rx="4" \
fill="{lane.color}" />
    <rect x="20" y="{middle - 5:.1f}" width="10" height="10" rx="2" fill="{lane.color}" />
    <text x="36" y="{middle - 3:.1f}" class="name">{lane.name}</text>
    <text x="36" y="{middle + 10:.1f}" class="rate">{rate:,.0f} decodes/s</text>
    <g id="badge-{lane.key}" opacity="0">
      <text x="{badge_x}" y="{middle + 4:.1f}" class="badge" fill="{lane.color}">\
&#x2713; {self._seconds(lane):.2f}s</text>
    </g>
  </g>"""

    def _axis(self) -> str:
        """The time axis: gridlines and labels, in seconds of race time."""
        lines: list[str] = []
        for i in range(self.axis_ticks):
            fraction = i / (self.axis_ticks - 1)
            x = self.track_x + fraction * self.track_width
            seconds = fraction * self._race_seconds()
            lines.append(
                f'    <line x1="{x:.1f}" y1="46" x2="{x:.1f}" y2="{self._axis_bottom()}" '
                'class="grid" />'
            )
            lines.append(
                f'    <text x="{x:.1f}" y="40" class="tick" text-anchor="middle">'
                f"{seconds:.1f}s</text>"
            )
        return "\n".join(lines)

    def render(self) -> str:
        loop = self._loop_seconds()
        race_end = self._race_seconds() / loop * 100
        footer_y = self._axis_bottom() + 26
        height = footer_y + 36
        fastest, slowest = self.lanes[0], self.lanes[-1]
        styles = "\n".join(self._lane_style(lane) for lane in self.lanes)
        lanes = "\n".join(self._lane(i, lane) for i, lane in enumerate(self.lanes))
        versions = ", ".join(lane.version for lane in self.lanes)
        return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{height}" \
viewBox="0 0 {self.width} {height}">
  <title>{self._title()}</title>
  <desc>{len(self.lanes)} JWT libraries each decode {self.decodes:,} tokens ({self._setup()}), \
the bars filling in real time. {fastest.name} finishes in {self._seconds(fastest):.2f}s, \
{slowest.name} in {self._seconds(slowest):.2f}s. Versions: {versions}.</desc>
  <style>
    text {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }}
    .title {{ font-size: 15px; fill: #0b0b0b; font-weight: 600; }}
    .tick {{ font-size: 10px; fill: #898781; }}
    .name {{ font-size: 13px; fill: #0b0b0b; font-weight: 600; }}
    .rate {{ font-size: 10px; fill: #52514e; }}
    .caption {{ font-size: 11px; fill: #52514e; }}
    .badge {{ font-size: 12px; font-weight: 700; }}
    .track {{ fill: #f3f2ef; stroke: #e1e0d9; }}
    .grid {{ stroke: #e1e0d9; stroke-width: 1; }}
    .playhead {{ stroke: #0b0b0b; stroke-width: 1.5; opacity: 0.55; }}

    /* One {loop:.3f}s loop: the race runs for the first {race_end:.3f}%
       ({self._race_seconds():.3f}s, the slowest library's time), then every bar holds
       for {self.hold_seconds:g}s, so the finish times can be read, before it restarts. */
    #playhead {{ animation: playhead {loop:.3f}s linear infinite; }}
{styles}
    @keyframes playhead {{
      0% {{ transform: translateX(0); }}
      {race_end:.3f}% {{ transform: translateX({self.track_width}px); }}
      100% {{ transform: translateX({self.track_width}px); }}
    }}
  </style>

  <rect width="{self.width}" height="{height}" fill="#fcfcfb" />
  <text x="20" y="26" class="title">{self._title()}</text>

  <g>
    <line x1="{self.track_x}" y1="46" x2="{self.track_x + self.track_width}" y2="46" \
class="grid" />
{self._axis()}
    <g id="playhead">
      <line x1="{self.track_x}" y1="46" x2="{self.track_x}" y2="{self._axis_bottom()}" \
class="playhead" />
    </g>
  </g>

{lanes}

  <text x="20" y="{footer_y}" class="caption">{self._setup()}. Each bar takes \
{self.decodes:,} &#215; the library's mean time per decode.</text>
  <text x="20" y="{footer_y + 16}" class="caption">Measured in Docker, one container per \
library, each on one pinned CPU core.</text>
</svg>
"""


@dataclass(frozen=True, slots=True)
class Races:
    """The races, drawn from the matrix's results files."""

    results: dict[str, dict[str, Any]]  # by file name, without .json

    # A fixed colour per library, whatever its place; ryjwt's variants on one green ramp, the
    # lightest for the least work (a dict).
    lane_names: ClassVar[dict[str, tuple[str, str]]] = {
        "ryjwt-msgspec": ("ryjwt → Struct", "#009e00"),
        "ryjwt": ("ryjwt → dict", "#00c200"),
        "jsonwebtoken": ("jsonwebtoken", "#eb6834"),
        "fast-jwt": ("fast-jwt", "#4a3aa7"),
        "jose": ("jose", "#eda100"),
        "pyjwt": ("PyJWT", "#2a78d6"),
    }
    runtimes: ClassVar[dict[str, str]] = {"CPython": "Python", "Bun": "Bun", "Rust": "Rust"}
    races: ClassVar[list[Race]] = [
        Race("hmac", "typical-k64", "HS256", "a 64-byte secret", "perf-race.svg"),
        Race("pem", "typical-es256", "ES256", "a PEM public key", "perf-race-es256.svg"),
    ]

    def _row(self, key: str, race: Race) -> dict[str, Any]:
        """`key`'s result for `race`."""
        rows: list[dict[str, Any]] = self.results[key]["rows"]
        return next(r for r in rows if (r["source"], r["name"]) == (race.source, race.case))

    def _lane(self, key: str, race: Race) -> Lane:
        results = self.results[key]
        row = self._row(key, race)
        name, color = self.lane_names[key]
        runtime = self.runtimes[results["runtime"].split()[0]]
        return Lane(key, f"{name} ({runtime})", color, row["mean_us"], results["impl"])

    @classmethod
    def load(cls, results_dir: Path) -> Races:
        return cls({path.stem: json.loads(path.read_text()) for path in results_dir.glob("*.json")})

    def svg(self, race: Race, decodes: int) -> str:
        lanes = sorted((self._lane(key, race) for key in self.lane_names), key=_mean_us)
        token_bytes: int = self._row("pyjwt", race)["token_len"]
        return RaceSVG(race, lanes, decodes, token_bytes).render()


def _mean_us(lane: Lane) -> float:
    return lane.mean_us


def main(results: str = "results-matrix", decodes: int = 100_000) -> None:
    """Draws assets/perf-race.svg and assets/perf-race-es256.svg from bench/<results>/*.json, and
    the same into docs/assets/, for the docs site (Zensical only publishes files in docs/; the
    README links to assets/, which tests/test_docs.py checks they match)."""
    root = Path(__file__).parent.parent
    races = Races.load(root / "bench" / results)
    for race in races.races:
        svg = races.svg(race, decodes)
        for assets in (root / "assets", root / "docs" / "assets"):
            path = assets / race.output
            path.write_text(svg)
            Console().print(f"wrote {path.relative_to(root)}")
