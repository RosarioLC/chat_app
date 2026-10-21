from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Input, Label
from textual.worker import Worker, WorkerState
from functools import partial

from ui.widgets.now_playing_bar import NowPlayingBar
from ui.widgets.search_bar import SearchBar
from ui.widgets.search_result import SearchResults
from ui.widgets.next_track_card import NextTrackCard
from model.track import Track


class HomeScreen(Screen):
    """Home screen showing recommended tracks and the now-playing bar."""

    # Number of tracks to load per page.
    _PAGE_SIZE: int = 12

    def __init__(self, catalog: object, player: object) -> None:
        """Initialize the home screen.

        Args:
            catalog: Music catalog provider.
            player: Playback controller.
        """
        super().__init__()
        self._catalog = catalog
        self._player = player
        self._recommended: list[Track] = []
        self._shown_count: int = 0
        self._seen_ids: set[str] = set()

    def compose(self) -> ComposeResult:
        """Compose the home screen layout."""
        yield SearchBar()
        yield Label("HOME", id="home-title")
        yield SearchResults(widget_id="recommended")
        yield NextTrackCard()
        yield Footer()
        yield NowPlayingBar()

    def on_mount(self) -> None:
        """Load recommended tracks in the background."""
        self._player.set_playlist_context(False)
        self.run_worker(
            partial(self._catalog.get_recommended_tracks, self._PAGE_SIZE),
            name="home-recommendations",
            group="home",
            thread=True,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle completion of the recommendations worker."""
        # Handle initial recommendations.
        if event.worker.name == "home-recommendations" and event.state == WorkerState.SUCCESS:
            tracks: list[Track] = event.worker.result or []
            # Deduplicate against already-seen tracks.
            tracks = [t for t in tracks if t.provider_id not in self._seen_ids]
            if tracks:
                self._seen_ids.update(t.provider_id for t in tracks if t.provider_id)
                self._recommended = tracks
                self.query_one("#recommended", SearchResults).show_results(tracks)
                self._shown_count += len(tracks)
        # Handle subsequent recommendations (infinite scroll).
        elif event.worker.name == "home-recommendations-next" and event.state == WorkerState.SUCCESS:
            tracks: list[Track] = event.worker.result or []
            # Deduplicate against already-seen tracks.
            tracks = [t for t in tracks if t.provider_id not in self._seen_ids]
            if tracks:
                self._seen_ids.update(t.provider_id for t in tracks if t.provider_id)
                self._recommended.extend(tracks)
                self.query_one("#recommended", SearchResults).append_results(tracks)
                self._shown_count += len(tracks)

    def _load_more_if_needed(self) -> None:
        """Load more recommendations if we haven't already."""
        if self._shown_count == 0:
            return
        self.query_one("#recommended", SearchResults).show_loading_more()
        self.run_worker(
            partial(self._catalog.get_recommended_tracks, self._PAGE_SIZE),
            name="home-recommendations-next",
            group="home",
            thread=True,
        )

    def on_search_results_load_more(self, event: SearchResults.LoadMore) -> None:
        """Handle LoadMore message from the recommended DataTable."""
        self._load_more_if_needed()


    def on_search_results_track_selected(self, event: SearchResults.TrackSelected) -> None:
        """Handle a track selection from the results table."""
        if event.row < len(self._recommended):
            self._player.set_continuation(self._recommended[event.row + 1:])
            self._player.play(self._recommended[event.row])

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Navigate to the search screen when the user submits a query."""
        setattr(self.app, "_pending_search_query", event.value.strip())
        await self.app.run_action("go_search")
