#!yeet
"""Render the raster icons from the hand-built favicon.svg (the leaf "r" mark): `task icons`.

- assets/favicon-32.png: 32x32, transparent.
- assets/favicon.ico: 16x16, 32x32 and 48x48, transparent.
- assets/apple-touch-icon.png: 180x180, the mark on solid white (iOS shows transparency as black).

Also copies favicon.svg to docs/assets/, which the docs site uses as its favicon and header logo
(Zensical only publishes files in docs/; tests/test_docs.py checks the copy matches).

Each size is rendered from the SVG by rsvg-convert (librsvg: `brew install librsvg`), not scaled
down from a larger raster, so the small sizes stay sharp.
"""

import io
import shutil
import subprocess
from pathlib import Path

from PIL import Image
from rich.console import Console

ICO_SIZES = (16, 32, 48)
APPLE_TOUCH_SIZE = 180
APPLE_TOUCH_MARK = 144
"""The mark's size inside the apple-touch icon: iOS rounds the corners, so it gets a margin."""


def _render(rsvg: str, svg: Path, size: int) -> Image.Image:
    """`svg` rendered by rsvg-convert at `size` x `size`, as RGBA."""
    command = [rsvg, "--width", str(size), "--height", str(size), str(svg)]
    png = subprocess.run(command, check=True, capture_output=True).stdout
    return Image.open(io.BytesIO(png)).convert("RGBA")


def _apple_touch_icon(rsvg: str, svg: Path) -> Image.Image:
    """The mark centred on a solid white square."""
    icon = Image.new("RGBA", (APPLE_TOUCH_SIZE, APPLE_TOUCH_SIZE), "white")
    offset = (APPLE_TOUCH_SIZE - APPLE_TOUCH_MARK) // 2
    icon.alpha_composite(_render(rsvg, svg, APPLE_TOUCH_MARK), (offset, offset))
    return icon.convert("RGB")


def main() -> None:
    """Writes assets/favicon-32.png, assets/favicon.ico and assets/apple-touch-icon.png from
    assets/favicon.svg, and copies favicon.svg to docs/assets/."""
    rsvg = shutil.which("rsvg-convert")
    if rsvg is None:
        raise SystemExit("rsvg-convert isn't installed: brew install librsvg")
    assets = Path(__file__).parent
    root = assets.parent
    svg = assets / "favicon.svg"
    console = Console()

    _render(rsvg, svg, 32).save(assets / "favicon-32.png", optimize=True)
    ico = [_render(rsvg, svg, size) for size in ICO_SIZES]
    ico[-1].save(
        assets / "favicon.ico", sizes=[image.size for image in ico], append_images=ico[:-1]
    )
    _apple_touch_icon(rsvg, svg).save(assets / "apple-touch-icon.png", optimize=True)
    shutil.copyfile(svg, root / "docs" / "assets" / svg.name)
    for name in ("favicon-32.png", "favicon.ico", "apple-touch-icon.png"):
        console.print(f"wrote assets/{name}")
    console.print(f"copied assets/{svg.name} to docs/assets/{svg.name}")
