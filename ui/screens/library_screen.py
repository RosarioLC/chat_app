from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label, Static

from catalog.catalog_source import CatalogSource
from playback.player import Player
from model.playlist import Playlist
from store.playlist_store import PlaylistStore
from ui.widgets.modal import NewPlaylistScreen, PlaylistPickerScreen
from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.next_track_card import NextTrackCard


class LibraryScreen(Screen):
    """Library screen with playlists and liked songs tables."""

    BINDINGS = [
        Binding("n", "new_playlist", "New Playlist"),
        Binding("d", "delete_playlist", "Delete Playlist"),
        Binding("a", "add_selected_to_playlist", "Add to Playlist"),
    ]

    def __init__(
        self,
        player: Player,
        catalog: CatalogSource,
        playlists: PlaylistStore,
    ) -> None:
        """Initialize the library screen.

        Args:
            player: Playback controller.
            catalog: Music catalog provider.
            playlists: Playlist persistence store.
        """
        super().__init__()
        self._player = player
        self._catalog = catalog
        self._playlists = playlists

    def compose(self) -> ComposeResult:
        """Compose the library screen layout."""
        yield Label("Library", id="library-title")
        yield DataTable(id="playlists")
        yield DataTable(id="liked-songs")
        yield NextTrackCard()
        yield Footer()
        yield NowPlayingBar()

    def on_mount(self) -> None:
        """Populate the playlists and liked-songs tables."""
        # Playlists table.
        playlists_table = self.query_one("#playlists", DataTable)
        playlists_table.add_columns("Name")
        for playlist in self._playlists.list():
            playlists_table.add_row(playlist.name, key=str(playlist.id))

        # Liked songs table.
        liked_table = self.query_one("#liked-songs", DataTable)
        liked_table.add_columns("Track ID")
        for row in self._playlists._db.fetchall(
            "SELECT track_id FROM liked_songs ORDER BY track_id"
        ):
            liked_table.add_row(str(row["track_id"]), key=str(row["track_id"]))

    def action_new_playlist(self) -> None:
        """Show the new playlist dialog."""
        self.call_after_refresh(lambda: self.app.push_screen(NewPlaylistScreen()))

    def on_mount_new_playlist(self, message: NewPlaylistScreen) -> None:
        """Handle the new playlist modal result."""
        name = message.result
        if name:
            try:
                playlist = self._playlists.create(name)
                self._refresh_playlists()
                self.notify(f'Playlist "{name}" created')
            except Exception as exc:
                self.notify(str(exc), severity="error")

    def action_delete_playlist(self) -> None:
        """Delete the currently selected playlist."""
        table = self.query_one("#playlists", DataTable)
        cursor = table.cursor_coordinate
        if cursor is None:
            self.notify("Select a playlist to delete", severity="warning")
            return
        playlists = self._playlists.list()
        if cursor.row >= len(playlists):
            return
        playlist = playlists[cursor.row]
        try:
            self._playlists.delete(playlist.id)
            self._refresh_playlists()
            self.notify(f'Playlist "{playlist.name}" deleted')
        except Exception as exc:
            self.notify(str(exc), severity="error")

    def action_add_selected_to_playlist(self) -> None:
        """Prompt user to choose a playlist for the currently playing track."""
        current = self._player.current_track
        if current is None:
            self.notify("Nothing is playing", severity="warning")
            return
        playlists = self._playlists.list()
        if not playlists:
            self.notify("Create a playlist first (N)", severity="warning")
            return
        self.app.push_screen(PlaylistPickerScreen(playlists))

    def on_mount_playlist_picker(self, message: PlaylistPickerScreen) -> None:
        """Handle the playlist picker result."""
        playlist_id = message.result
        if playlist_id is None:
            return
        current = self._player.current_track
        if current is None:
            return
        try:
            playlists = self._playlists.list()
            for p in playlists:
                if p.id == playlist_id:
                    p.add_song(current)
                    self.notify(f'Added to "{p.name}"')
                    break
        except ValueError as exc:
            self.notify(str(exc), severity="error")
        except Exception as exc:
            self.notify(str(exc), severity="error")

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Open the playlist screen when a playlist row is selected."""
        if event.data_table.id != "playlists":
            return
        row = event.coordinate.row
        playlists = self._playlists.list()
        if row >= len(playlists):
            return
        playlist_id = playlists[row].id
        playlist = next(
            (item for item in self._playlists.list() if item.id == playlist_id),
            None,
        )
        if playlist is not None and self.app is not None:
            from ui.screens.playlist_screen import PlaylistScreen
            self.app.push_screen(
                PlaylistScreen(player=self._player, playlist=playlist)
            )

    def _refresh_playlists(self) -> None:
        """Rebuild the playlists table from the store."""
        table = self.query_one("#playlists", DataTable)
        table.clear()
        table.add_columns("Name")
        for playlist in self._playlists.list():
            table.add_row(playlist.name, key=str(playlist.id))
