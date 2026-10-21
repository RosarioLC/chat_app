from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Label, Footer
from functools import partial

from catalog.ytmusic_source import YTMusicSource
from playback.player import Player
from model.track import Track
from ui.widgets.lyrics_panel import LyricsPanel
from ui.widgets.now_playing_bar import NowPlayingBar


# Interval between lyric highlight refreshes (seconds).
_HIGHLIGHT_INTERVAL: float = 0.25


class LyricsScreen(Screen):
    """Overlay screen displaying synced lyrics for the current track."""

    CSS = """
    ListView {
        scrollbar-color: #535353;
        scrollbar-color-hover: #535353;
        scrollbar-color-active: #535353;
        scrollbar-background: #121212;
    }
    ListView:focus {
        scrollbar-color: #737373;
    }
    """

    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, player: Player, catalog: YTMusicSource) -> None:
        """Initialize the lyrics screen.

        Args:
            player: Playback controller.
            catalog: Music catalog provider.
        """
        super().__init__(id="lyrics-screen")
        self._player = player
        self._catalog = catalog
        # Cached DOM references for fast access.
        self._lyrics_panel: LyricsPanel | None = None
        self._lyrics_title: Label | None = None

    def compose(self) -> ComposeResult:
        """Compose the lyrics screen layout."""
        yield Label("Lyrics", id="lyrics-title")
        yield LyricsPanel()
        yield Label("Press Escape to close", id="lyrics-help")
        yield Footer()
        yield NowPlayingBar(show_art=True)

    def on_mount(self) -> None:
        """Start periodic highlight refresh and load lyrics."""
        self._lyrics_panel = self.query_one(LyricsPanel)
        self._lyrics_title = self.query_one("#lyrics-title", Label)
        self.set_interval(_HIGHLIGHT_INTERVAL, self._refresh_highlight)
        track = self._player.current_track
        if track is None:
            self._lyrics_panel.set_message("Nothing is playing")
            return
        self._lyrics_title.update(
            f"{track.title}  /  {track.artist}"
        )
        self.run_worker(
            partial(self._load_lyrics, track),
            name="lyrics-load",
            group="lyrics",
            thread=True,
        )

    def _refresh_highlight(self) -> None:
        """Update the highlighted lyric line based on current playback position."""
        self._lyrics_panel.update_highlight(self._player.position_ms)

    def _load_lyrics(self, track: Track) -> list:
        """Fetch lyrics via the app's cached lyrics method."""
        return getattr(self.app, "get_lyrics")(track)

    def on_worker_state_changed(self, event: object) -> None:
        """Handle lyrics load completion."""
        if event.worker.name != "lyrics-load":
            return

        panel = self.query_one(LyricsPanel)

        if event.worker.state.name == "SUCCESS":
            lines = event.worker.result
            if lines:
                panel.set_lyrics(lines)
            else:
                panel.set_message("Lyrics are not available for this track")
        elif event.worker.state.name == "ERROR":
            panel.set_message("Unable to load lyrics")

    def action_close(self) -> None:
        """Dismiss the lyrics overlay."""
        self.app.pop_screen()
