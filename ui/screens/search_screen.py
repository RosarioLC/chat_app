from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, Static
from collections.abc import Callable

from catalog.catalog_source import CatalogSource
from model.track import Track
from ui.widgets.search_input import SearchInput
from ui.widgets.search_bar import SearchBar
from ui.widgets.search_result import SearchResults
from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.next_track_card import NextTrackCard


class SearchScreen(Screen):
    """Search screen for querying the music catalog."""

    def __init__(
        self,
        catalog: CatalogSource,
        player: object,
        initial_query: str = "",
        initial_tracks: list[Track] | None = None,
        on_results: Callable[[str, list[Track]], None] | None = None,
    ) -> None:
        """Initialize the search screen.

        Args:
            catalog: Music catalog provider.
            player: Playback controller.
            initial_query: Pre-filled search query.
            initial_tracks: Pre-loaded search results (e.g. from a previous search).
            on_results: Optional callback invoked when search results arrive.
        """
        super().__init__()
        self._catalog = catalog
        self._player = player
        self._query: str = initial_query
        self._tracks: list[Track] = list(initial_tracks or [])
        self._on_results_callback: Callable[[str, list[Track]], None] | None = on_results
        # Cached DOM reference.
        self._search_box: SearchInput | None = None

    def on_search_results_track_selected(self, event: SearchResults.TrackSelected) -> None:
        """Handle a track selection from the results table."""
        self._on_track_selected(event)

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Handle a cell selection (fallback for DataTable-based selection)."""
        row = event.coordinate.row
        if row < len(self._tracks):
            self._on_track_selected(event)

    def _on_track_selected(self, event: SearchResults.TrackSelected) -> None:
        """Handle a track selection from the results table."""
        if event.row < len(self._tracks):
            self._player.set_continuation(self._tracks[event.row + 1:])
            self._player.play(self._tracks[event.row])
            if self._player._app is not None and hasattr(self._player._app, "preload_search_results"):
                self._player._app.preload_search_results(self._tracks)

    def compose(self) -> ComposeResult:
        """Compose the search screen layout."""
        yield SearchBar()
        yield SearchResults()
        yield NextTrackCard()
        yield Footer()
        yield NowPlayingBar()

    def on_mount(self) -> None:
        """Restore the search box value and trigger search if needed."""
        self._search_box = self.query_one(SearchInput)
        self._search_box.value = self._query
        if self._tracks:
            self.query_one(SearchResults).show_results(self._tracks)
        elif self._query:
            self._search(self._query)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Search when the user submits a query."""
        self._search(event.value.strip())

    def _search(self, query: str) -> None:
        """Execute a search and update the results widget.

        Args:
            query: The search query string.
        """
        self._query = query
        results_widget = self.query_one(SearchResults)
        if not query:
            results_widget.show_error("Type an artist or song title to search")
            return
        results_widget.show_loading()
        try:
            results = self._catalog.search(query)
        except Exception as error:
            results_widget.show_error(str(error))
            return
        self._on_search_results(results)

    def _on_search_results(self, results: list[Track]) -> None:
        """Handle completed search results.

        Args:
            results: List of matching tracks.
        """
        self._tracks = results
        if self._on_results_callback:
            self._on_results_callback(self._query, results)
        self.query_one(SearchResults).show_results(results)

    def on_search_results_track_selected(self, event: SearchResults.TrackSelected) -> None:
        """Handle a track selection from the results table."""
        if event.row < len(self._tracks):
            self._player.set_continuation(self._tracks[event.row + 1:])
            self._player.play(self._tracks[event.row])
            if hasattr(self._player._app, "preload_search_results"):
                self._player._app.preload_search_results(self._tracks)

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Handle a cell selection (fallback for DataTable-based selection)."""
        row = event.coordinate.row
        if row < len(self._tracks):
            self._player.set_continuation(self._tracks[row + 1:])
            self._player.play(self._tracks[row])
            if hasattr(self._player._app, "preload_search_results"):
                self._player._app.preload_search_results(self._tracks)
