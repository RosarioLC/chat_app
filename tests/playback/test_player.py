import pytest
from playback.player import Player
from playback.music_queue import MusicQueue
from tests.playback.fake_backend import FakeBackend
from model.track import Track


class TestPlayer:
    def test_create(self):
        backend = FakeBackend()
        queue = MusicQueue()
        player = Player(backend=backend, queue=queue)
        assert player.is_playing is False

    def test_play(self):
        backend = FakeBackend()
        queue = MusicQueue()
        player = Player(backend=backend, queue=queue)
        t = Track(id=1, title="Test")
        queue._tracks = [t]
        player.play(t)
        assert player.is_playing is True
