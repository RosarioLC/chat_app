from typing_extensions import Protocol


class AudioBackend(Protocol):
    """Interface for audio playback backends (VLC, etc.).

    Any class implementing this protocol can be used as the backend
    for :class:`~playback.player.Player`.
    """

    def play(self, url: str) -> None:
        """Start playback of the media at *url*."""
        ...

    def pause(self) -> None:
        """Pause playback."""
        ...

    def resume(self) -> None:
        """Resume paused playback."""
        ...

    def stop(self) -> None:
        """Stop playback."""
        ...

    def seek(self, position_ms: int) -> None:
        """Seek to *position_ms* within the currently playing media."""
        ...

    def get_position(self) -> int:
        """Return the current playback position in milliseconds."""
        ...

    def get_duration(self) -> int:
        """Return the total duration of the current media in milliseconds."""
        ...

    def set_volume(self, volume: int) -> None:
        """Set the playback volume (0–100)."""
        ...

    def get_volume(self) -> int:
        """Return the current volume (0–100)."""
        ...

    @property
    def is_playing(self) -> bool:
        """``True`` if playback is currently active."""
        ...

    @property
    def is_paused(self) -> bool:
        """``True`` if playback is paused."""
        ...
