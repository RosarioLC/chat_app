import pytest
from catalog.lyrics_provider import LyricsProvider
from model.track import Track
from model.lyric_line import LyricLine


class TestLyricsProvider:
    def test_fetch_empty(self):
        track = Track(id=1, title="Test", artist="Artist")
        provider = LyricsProvider()
        result = provider.fetch(track)
        assert result == []
