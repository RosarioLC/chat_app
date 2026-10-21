"""Represents a single line of synchronized lyrics."""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class LyricLine:
    """A single line of lyrics with an associated timestamp.

    Attributes:
        timestamp_ms: When this line should appear, in milliseconds.
        text: The lyric text to display.
    """

    timestamp_ms: int
    text: str