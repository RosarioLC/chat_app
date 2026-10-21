import pytest
from model.play_state import PlayState


class TestPlayState:
    def test_initial(self):
        ps = PlayState()
        assert ps.is_playing is False
        assert ps.is_paused is False

    def test_replace_playing(self):
        ps = PlayState()
        new_ps = ps.replace(is_playing=True)
        assert new_ps.is_playing is True
        assert new_ps.is_paused is False
        # Original should be unchanged
        assert ps.is_playing is False
