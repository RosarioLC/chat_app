from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label

from catalog.catalog_source import CatalogSource
from playback.player import Player
from model.playlist import Playlist
from store.playlist_store import PlaylistStore
from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.next_track_card import NextTrackCard


class LibraryScreen(Screen):
    """Library screen with playlists and liked songs tables."""

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
