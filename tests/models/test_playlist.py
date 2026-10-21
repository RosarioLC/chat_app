import pytest
from model.track import Track
from model.playlist import Playlist


class TestPlaylist:
    def test_create(self):
        p = Playlist(id=1, name="Test", songs=[])
        assert p.id == 1
        assert p.name == "Test"
        assert p.songs == []

    def test_add_song(self):
        p = Playlist(id=1, name="Test", songs=[])
        t = Track(id=1, title="Test")
        p.add_song(t)
        assert len(p.songs) == 1

    def test_remove_song(self):
        t = Track(id=1, title="Test")
        p = Playlist(id=1, name="Test", songs=[t])
        p.remove_song(t)
        assert len(p.songs) == 0
