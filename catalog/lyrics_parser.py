from model.lyric_line import LyricLine
import re


# Regex for LRC timestamp lines: [mm:ss.xx] text
# Groups: 1=minutes, 2=seconds, 3=centiseconds (optional), 4=text
_LRC_PATTERN: re.Pattern[str] = re.compile(
    r"^\[(\d{1,2}):(\d{2})(?:\.(\d{1,3}))?\]\s*(.*)$"
)


class LyricsParser:
    """Parse LRC-formatted lyrics into :class:`~model.lyric_line.LyricLine` objects."""

    @staticmethod
    def parse(raw_text: str) -> list[LyricLine]:
        """Parse LRC-format lyrics text into a list of :class:`~model.lyric_line.LyricLine`.

        Lines that do not match the expected ``[mm:ss.xx] text`` format are silently
        skipped.  Centiseconds (the ``.xx`` part) are optional and padded to
        milliseconds on the right.

        Args:
            raw_text: Raw LRC-formatted lyrics.

        Returns:
            A list of :class:`~model.lyric_line.LyricLine` objects sorted in order
            of appearance in the source text.
        """
        lines: list[LyricLine] = []
        for raw_line in raw_text.splitlines():
            match = _LRC_PATTERN.match(raw_line.strip())
            if match is None:
                continue
            minutes, seconds, fraction, text = match.groups()
            milliseconds = int((fraction or "0").ljust(3, "0"))
            timestamp_ms = (
                int(minutes) * 60_000
                + int(seconds) * 1_000
                + milliseconds
            )
            lines.append(LyricLine(timestamp_ms=timestamp_ms, text=text))
        return lines
