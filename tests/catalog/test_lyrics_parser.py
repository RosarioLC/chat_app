import pytest
from catalog.lyrics_parser import LyricsParser
from model.lyric_line import LyricLine


class TestLyricsParser:
    def test_parse_empty(self):
        result = LyricsParser.parse("")
        assert result == []

    def test_parse_simple(self):
        text = "[00:00.00]First line\n[00:01.00]Second line"
        result = LyricsParser.parse(text)
        assert len(result) == 2
        assert isinstance(result[0], LyricLine)
