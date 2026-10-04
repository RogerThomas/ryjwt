#!uv run
import logging
from pathlib import Path

logger = logging.getLogger("Main")


def main(n: int, pdf_path: Path) -> None:
    logger.info("n: %s, path: %s", n, pdf_path)
