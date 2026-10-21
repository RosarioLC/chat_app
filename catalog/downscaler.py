"""Convert images to ANSI half-block colour text for terminal display."""

from __future__ import annotations

from functools import lru_cache
from io import BytesIO
from urllib.request import urlopen
from typing import TYPE_CHECKING

import numpy as np
from PIL import Image

# Default rendering parameters.
DEFAULT_COLS: int = 24
CELL_ASPECT: float = 2.1

# Pre-compiled format string for ANSI escape sequences.
_ANSI_FMT: str = "\x1b[48;2;{};{};{}m\x1b[38;2;{};{};{}m\u2584"

if TYPE_CHECKING:
    pass  # No type-only imports needed at the moment.


@lru_cache(maxsize=128)
def _read_image(source: str) -> bytes:
    """Read an image from a local file or URL.

    Args:
        source: File path or HTTP(S) URL.

    Returns:
        The raw image bytes.
    """
    if source.startswith(("http://", "https://")):
        with urlopen(source, timeout=10) as response:
            return response.read()
    with open(source, "rb") as image_file:
        return image_file.read()


@lru_cache(maxsize=64)
def downscale(
    image_path: str,
    cols: int = DEFAULT_COLS,
    cell_aspect: float = CELL_ASPECT,

) -> str:
    """Downscale an image to ANSI half-block colour text.

    The image is resampled to a grid of *cols* columns, with two pixel
    rows combined into one ANSI half-block character (using the top row
    for background colour and the bottom row for foreground colour).

    Args:
        image_path: Path to the image file or an HTTP(S) URL.
        cols: Number of character columns in the output.
        cell_aspect: Aspect ratio of a character cell (width / height).

    Returns:
        ANSI-escaped text rendering of the image.
    """
    text_rows: int = max(1, round(cols / cell_aspect))
    W: int = cols
    H: int = text_rows * 2
    image = Image.open(BytesIO(_read_image(image_path)))

    with image:
        image = image.convert("RGB")
        image = image.resize((W, H), Image.BICUBIC)
        arr: np.ndarray = np.asarray(image)

        # Build ANSI half-block output (two pixel rows -> one half-block).
        # Pre-convert to list for faster indexing.
        rows_list: list[np.ndarray] = arr.tolist()
        lines: list[str] = []
        for ty in range(0, H, 2):
            top: list[list[int]] = rows_list[ty]
            bot: list[list[int]] = rows_list[ty + 1]
            # Build the line using list comprehension (faster than generator for join).
            line_parts: list[str] = [
                _ANSI_FMT.format(a[0], a[1], a[2], b[0], b[1], b[2])
                for a, b in zip(top, bot)
            ]
            lines.append("".join(line_parts))
        result = "\n".join(lines)

    return result
