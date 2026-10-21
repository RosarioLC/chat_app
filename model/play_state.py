"""Immutable playback state used by the UI and player."""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PlayState:
    """Immutable playback state used by the UI and player.

    Attributes:
        is_playing: Whether playback is currently active.
        is_paused: Whether playback is paused.
    """

    is_playing: bool = False
    is_paused: bool = False

    def replace(self, **changes: object) -> "PlayState":
        """Return a new PlayState with the given fields replaced."""
        from dataclasses import replace as _dc_replace
        return _dc_replace(self, **changes)  # type: ignore[call-overload]
