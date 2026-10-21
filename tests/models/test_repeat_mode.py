import pytest
from model.repeat_mode import RepeatMode


class TestRepeatMode:
    def test_values(self):
        assert RepeatMode.OFF.value == 0
        assert RepeatMode.ALL.value == 1
        assert RepeatMode.ONE.value == 2
