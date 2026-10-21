from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label

from model.playlist import Playlist
from playback.player import Player
from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.next_track_card import NextTrackCard


class PlaylistScreen(Screen):
    """Screen showing a single playlist's tracks."""

    BINDINGS = [
        Binding("d", "remove_song", "Remove Song"),
        Binding("escape", "go_back", "Back"),
    ]

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

    def action_remove_song(self) -> None:
        """Remove the currently selected track from the playlist."""
        table = self.query_one("#playlist-tracks", DataTable)
        cursor = table.cursor_coordinate
        if cursor is None:
            self.notify("Select a song to remove", severity="warning")
            return
        songs = self._playlist.songs
        if cursor.row >= len(songs):
            return
        track = songs[cursor.row]
        try:
            self._playlist.remove_song(track)
            self._refresh_table()
            self.notify(f'Removed "{track.title}"')
        except ValueError as exc:
            self.notify(str(exc), severity="error")

    def action_go_back(self) -> None:
        """Return to the previous screen."""
        if self.app and len(self.app.screen_stack) > 1:
            self.app.pop_screen()

    def _refresh_table(self) -> None:
        """Rebuild the tracks table from the playlist."""
        table = self.query_one("#playlist-tracks", DataTable)
        table.clear()
        table.add_columns("Title", "Artist", "Album")
        for index, track in enumerate(self._playlist.songs):
            table.add_row(track.title, track.artist, track.album, key=str(index))
