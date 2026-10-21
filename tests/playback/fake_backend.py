from playback.audio_backend import AudioBackend


class FakeBackend(AudioBackend):
    def __init__(self):
        self._playing = False
        self._paused = False
        self._volume = 75
        self._position_ms = 0

    def play(self, url: str) -> None:
        self._playing = True
        self._paused = False

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def stop(self) -> None:
        self._playing = False

    def seek(self, position_ms: int) -> None:
        self._position_ms = position_ms

    def get_position(self) -> int:
        return self._position_ms

    def get_duration(self) -> int:
        return 180000

    def set_volume(self, volume: int) -> None:
        self._volume = volume

    def get_volume(self) -> int:
        return self._volume

    @property
    def is_playing(self) -> bool:
        return self._playing and not self._paused

    @property
    def is_paused(self) -> bool:
        return self._paused
