from textual.app import ComposeResult
from textual.widgets import Label, Static
from textual.css.query import NoMatches

from model.track import Track
from ui.widgets.album_art import AlbumArt


# Refresh interval for the next-track preview (seconds).
_REFRESH_INTERVAL: float = 0.5


class NextTrackDetails(Static):
    """Container for next-track album art and metadata."""

    def __init__(self) -> None:
        """Initialize the next-track details widget."""
        super().__init__(id="next-track-details")

    def compose(self) -> ComposeResult:
        """Compose the album art and metadata."""
        yield AlbumArt(art_cols=16, id="next-art")
        yield NextTrackText()


class NextTrackText(Static):
    """Vertical container for NEXT label and metadata."""

    def __init__(self) -> None:
        """Initialize the next-track text container."""
        super().__init__(id="next-text")

    def compose(self) -> ComposeResult:
        """Compose the NEXT label and metadata display."""
        yield Label("NEXT", id="next-label")
        yield Static("", id="next-metadata")


class NextTrackCard(Static):
    """Compact next-track preview for the Home screen."""

    def __init__(self) -> None:
        """Initialize the next-track card."""
        super().__init__(id="next-track")
        self._player_ref: object | None = None

    def compose(self) -> ComposeResult:
        """Compose the next-track details."""
        yield NextTrackDetails()

    def on_mount(self) -> None:
        """Start periodic refresh from the player."""
        if self.app and hasattr(self.app, "_player"):
            self._player_ref = getattr(self.app, "_player")
        self.set_interval(_REFRESH_INTERVAL, self._refresh)

    def _refresh(self) -> None:
        """Update the card with the next track's info."""
        player = self._player_ref
        if player is None:
            return
        try:
            metadata = self.query_one("#next-metadata", Static)
            art = self.query_one("#next-art", AlbumArt)
        except NoMatches:
            return
        track = player.upcoming_track
        if track is None:
            self.display = False
            return
        self.display = True
        metadata.update(f"{track.title}\n{track.artist}")
        art.set_source(track.image_path)
