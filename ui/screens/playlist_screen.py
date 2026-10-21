from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label

from model.playlist import Playlist
from playback.player import Player
from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.next_track_card import NextTrackCard


class PlaylistScreen(Screen):
    """Screen showing a single playlist's tracks."""

    def __init__(self, player: Player, playlist: Playlist) -> None:
        """Initialize the playlist screen.

        Args:
            player: Playback controller.
            playlist: The playlist to display.
        """
        super().__init__()
        self._player = player
        self._playlist = playlist

    def compose(self) -> ComposeResult:
        """Compose the playlist screen layout."""
        yield Label(f"Playlist: {self._playlist.name}", id="playlist-name")
        yield DataTable(id="playlist-tracks")
        yield NextTrackCard()
        yield Footer()
        yield NowPlayingBar()

    def on_mount(self) -> None:
        """Populate the track table and enter playlist context."""
        self._player.set_playlist_context(True)
        table = self.query_one("#playlist-tracks", DataTable)
        table.add_columns("Title", "Artist", "Album")
        for index, track in enumerate(self._playlist.songs):
            table.add_row(track.title, track.artist, track.album, key=str(index))

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Play the selected track."""
        row = event.coordinate.row
        if row < len(self._playlist.songs):
            self._player.play(self._playlist.songs[row])
