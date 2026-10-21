from __future__ import annotations

from textual.widgets import Static
from textual.app import ComposeResult
from textual.reactive import reactive

from ui.widgets.track_info import TrackInfo
from ui.widgets.playback_center import PlaybackCenter
from ui.widgets.player_utilities import PlayerUtilities
from ui.widgets.track_progress import TrackProgress
from model.track import Track


# Interval between status refreshes (seconds).
_REFRESH_INTERVAL: float = 0.5


def _format_time(milliseconds: int) -> str:
    """Format milliseconds as ``mm:ss``.

    Args:
        milliseconds: Time in milliseconds.

    Returns:
        Formatted time string (e.g. ``"3:45"``).
    """
    total_seconds: int = max(milliseconds, 0) // 1000
    return f"{total_seconds // 60}:{total_seconds % 60:02d}"


class NowPlayingBar(Static):
    """Persistent bottom bar showing playback status and controls."""

    current_title: reactive[str] = reactive("")
    current_artist: reactive[str] = reactive("")
    progress_ms: reactive[int] = reactive(0)
    duration_ms: reactive[int] = reactive(0)
    is_playing: reactive[bool] = reactive(False)

    def __init__(self, show_art: bool = True) -> None:
        """Initialize the now-playing bar.

        Args:
            show_art: Whether to display album art.
        """
        super().__init__(id="now-playing")
        self._show_art: bool = show_art
        self._player_ref: object | None = None
        # Cached DOM references.
        self._current_time: Static | None = None
        self._track_progress: TrackProgress | None = None
        self._duration_time: Static | None = None

    def compose(self) -> ComposeResult:
        """Compose the now-playing bar layout."""
        yield TrackInfo(show_art=self._show_art)
        yield PlaybackCenter()
        yield PlayerUtilities()

    def on_mount(self) -> None:
        """Start periodic status refresh from the player."""
        if hasattr(self.app, "_player"):
            self._player_ref = getattr(self.app, "_player")
        self.set_interval(_REFRESH_INTERVAL, self._refresh_from_player)

        # Cache DOM references.
        try:
            self._current_time = self.query_one("#current-time", Static)
            self._track_progress = self.query_one(TrackProgress)
            self._duration_time = self.query_one("#duration-time", Static)
        except Exception:
            pass

    def _refresh_from_player(self) -> None:
        """Pull the latest playback state from the player and update UI."""
        player = self._player_ref
        if player is None:
            return
        self.update_track(player.current_track)
        self.progress_ms = player.position_ms
        self.duration_ms = player.duration_ms
        self.is_playing = player.is_playing

    def update_track(self, track: Track | None) -> None:
        """Update the track info display.

        Args:
            track: The current track, or ``None``.
        """
        self.query_one(TrackInfo).update_track(track)

    def watch_progress_ms(self, progress_ms: int) -> None:
        """React to progress changes: update time labels and slider."""
        if self._current_time is not None:
            self._current_time.update(_format_time(progress_ms))
        if self._track_progress is not None:
            self._track_progress.value = progress_ms

    def watch_duration_ms(self, duration_ms: int) -> None:
        """React to duration changes: update slider maximum and end time."""
        if self._track_progress is not None:
            self._track_progress.maximum = max(duration_ms, 1)
        if self._duration_time is not None:
            self._duration_time.update(_format_time(duration_ms))
