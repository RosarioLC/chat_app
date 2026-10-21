import pytest
from playback.music_queue import MusicQueue
from model.track import Track
from model.repeat_mode import RepeatMode


class TestMusicQueue:
    def test_create(self):
        q = MusicQueue()
        assert q.current is None
        assert q.is_empty is True

    def test_skip_to(self):
        t = Track(id=1, title="Test")
        q = MusicQueue(tracks=[t])
        q.skip_to(t)
        assert q.current == t

    def test_play_next(self):
        t1 = Track(id=1, title="1")
        t2 = Track(id=2, title="2")
        q = MusicQueue(tracks=[t1, t2])
        result = q.play_next()
        assert result == t1

    def test_toggle_repeat(self):
        q = MusicQueue()
        q.toggle_repeat()
        assert q._repeat == RepeatMode.ALL
        q.toggle_repeat()
        assert q._repeat == RepeatMode.ONE
        q.toggle_repeat()
        assert q._repeat == RepeatMode.OFF
