import pytest
from model.track import Track


class TestTrack:
    def test_create(self):
        t = Track(id=1, title="Test", artist="Artist")
        assert t.id == 1
        assert t.title == "Test"
        assert t.artist == "Artist"

    def test_to_dict(self):
        t = Track(id=1, title="Test", artist="Artist", album="Album", duration_ms=180000)
        d = t.to_dict()
        assert d["id"] == 1
        assert d["title"] == "Test"
        assert "url" in d

    def test_replace(self):
        t = Track(id=1, title="Old", artist="Old")
        new_t = t.replace(title="New", artist="New")
        assert new_t.id == 1  # ID should be unchanged
        assert new_t.title == "New"
        assert new_t.artist == "New"
        # Original should be unchanged (immutable)
        assert t.title == "Old"
        assert t.artist == "Old"
