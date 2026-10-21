from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding

from playback.music_queue import MusicQueue
from playback.player import Player
from playback.vlc_backend import VLCAudioBackend
from catalog.ytmusic_source import YTMusicSource
from catalog.track_cache import TrackCache
from model.track import Track
from store.database import Database
from store.playlist_store import PlaylistStore
from ui.screens.home_screen import HomeScreen
from ui.screens.search_screen import SearchScreen
from ui.screens.library_screen import LibraryScreen
from ui.screens.lyrics_screen import LyricsScreen
from ui.screens.fullscreen_screen import FullscreenScreen

if TYPE_CHECKING:
    pass


class MusicTUI(App):
    """Main application for the MusicTUI music player.

    Manages screen navigation, stream resolution, asset preloading,
    and delegates playback to a :class:`~playback.player.Player` instance.
    """

    CSS_PATH: str = "style.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("h", "go_home", "Home", show=True),
        Binding("s", "go_search", "Search", show=True),
        Binding("l", "go_library", "Library", show=True),
        Binding("f", "toggle_fullscreen", "Fullscreen", show=True),
    ]

    def on_mount(self) -> None:
        """Initialize services and push the home screen."""
        import sys

        sys.stdout.write("MUSIC_APP_MOUNTED\n")
        sys.stdout.flush()

        # Core services.
        self._catalog: YTMusicSource = YTMusicSource()
        self._store: Database = Database("store.db")
        self._playlists: PlaylistStore = PlaylistStore(self._store)
        self._track_cache: TrackCache = TrackCache(max_size=50)
        self._player: Player = Player(
            backend=VLCAudioBackend(),
            queue=MusicQueue(),
            stream_resolver=self._resolve_stream,
        )
        self._player.set_textual_app(self)

        # Search state.
        self._last_search_query: str = ""
        self._last_search_tracks: list[Track] = []
        self._pending_search_query: str = ""
        self._asset_workers: set[int] = set()

        self.push_screen(HomeScreen(self._catalog, self._player))

    def on_unmount(self) -> None:
        """Close the database connection on shutdown."""
        if hasattr(self, "_store"):
            self._store.close()

    def action_go_home(self) -> None:
        """Navigate to the home screen."""
        self.switch_screen(HomeScreen(self._catalog, self._player))

    def action_go_search(self) -> None:
        """Navigate to the search screen, preserving the last query."""
        self._player.set_playlist_context(False)
        query = self._pending_search_query or self._last_search_query
        self._pending_search_query = ""
        self.switch_screen(
            SearchScreen(
                catalog=self._catalog,
                player=self._player,
                initial_query=query,
                initial_tracks=self._last_search_tracks,
                on_results=self._remember_search,
            )
        )

    def action_go_library(self) -> None:
        """Navigate to the library screen."""
        self._player.set_playlist_context(False)
        self.switch_screen(
            LibraryScreen(
                player=self._player,
                catalog=self._catalog,
                playlists=self._playlists,
            )
        )

    def _remember_search(self, query: str, tracks: list[Track]) -> None:
        """Callback invoked by the search screen when results are returned."""
        self._last_search_query = query
        self._last_search_tracks = list(tracks)

    def _resolve_stream(self, track: Track) -> str:
        """Resolve a playable stream URL for *track*, using the cache."""
        cached = self._track_cache.get_stream(track.id)
        if cached is not None:
            return cached
        stream = self._catalog.get_track_stream_url(track)
        if stream:
            self._track_cache.put_stream(track.id, stream)
        return stream

    def preload_track(self, track: Track) -> None:
        """Preload lyrics and stream URL for *track* in the background.

        Skips tracks that are already being loaded or already cached.
        """
        if track.id in self._asset_workers:
            return
        if self._track_cache.get_lyrics(track.id) is not None:
            return

        self._asset_workers.add(track.id)
        self.run_worker(
            partial(self._load_track_assets, track),
            name=f"track-assets-{track.id}",
            thread=True,
            group="track-assets",
            exit_on_error=False,
        )

    def preload_search_results(self, tracks: list[Track]) -> None:
        """Preload assets for the top 20 search result tracks."""
        for track in tracks[:20]:
            self.preload_track(track)

    def preload_from_search(self, tracks: list[Track]) -> None:
        """Preload assets for the first 10 tracks in the result list."""
        for track in tracks[:10]:
            self.preload_track(track)

    def preload_next_tracks(self, current: Track) -> None:
        """Preload the next 3 tracks in the queue after *current*."""
        for index, track in enumerate(self._player.queue):
            if index >= 3:
                break
            if track.id != current.id:
                self.preload_track(track)

    def _load_track_assets(self, track: Track) -> None:
        """Background worker: resolve stream URL and fetch lyrics."""
        self._resolve_stream(track)
        self._track_cache.put_lyrics(track.id, self._catalog.get_lyrics(track))

    def get_lyrics(self, track: Track) -> list:
        """Fetch lyrics for *track*, using the cache when available."""
        cached = self._track_cache.get_lyrics(track.id)
        if cached is not None:
            return cached
        lyrics = self._catalog.get_lyrics(track)
        self._track_cache.put_lyrics(track.id, lyrics)
        return lyrics

    def on_worker_state_changed(self, event: object) -> None:
        """When a track-asset worker finishes, preload the next tracks."""
        worker_name = getattr(event, "worker", None)
        name = worker_name.name if worker_name else ""
        if not name.startswith("track-assets-"):
            return

        track_id = int(name.removeprefix("track-assets-"))
        self._asset_workers.discard(track_id)

        cache = self._track_cache.get(track_id)
        if cache and self._player.is_playing:
            self.preload_next_tracks(cache)

    async def action_show_lyrics(self) -> None:
        """Toggle the lyrics overlay screen."""
        if isinstance(self.screen, LyricsScreen):
            self.pop_screen()
            return

        existing = next(
            (
                screen
                for screen in self.screen_stack
                if isinstance(screen, LyricsScreen)
            ),
            None,
        )
        if existing is not None:
            while self.screen is not existing:
                self.pop_screen()
            return

        if self._player.current_track is None:
            self.notify("Nothing is playing")
            return
        self.push_screen(LyricsScreen(self._player, self._catalog))

    async def action_toggle_fullscreen(self) -> None:
        """Toggle the fullscreen album-art overlay screen."""
        if isinstance(self.screen, FullscreenScreen):
            self.pop_screen()
            return

        existing = next(
            (
                screen
                for screen in self.screen_stack
                if isinstance(screen, FullscreenScreen)
            ),
            None,
        )
        if existing is not None:
            while self.screen is not existing:
                self.pop_screen()
            return

        track = self._player.current_track
        if track is None:
            self.notify("Nothing is playing")
            return
        self.push_screen(FullscreenScreen(track))
