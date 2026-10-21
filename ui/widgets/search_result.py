from __future__ import annotations

from datetime import timedelta
from functools import partial
from typing import cast

from rich.text import Text
from rich.style import Style
from textual.coordinate import Coordinate
from textual.events import Click, MouseMove, MouseScrollDown, MouseScrollUp
from textual.message import Message
from textual.widgets import DataTable
from textual.widgets._data_table import SegmentLines
from textual.worker import Worker, WorkerState

from catalog.downscaler import downscale
from model.track import Track

# Cached null style to avoid repeated construction.
_NULL_STYLE: Style = Style.null()

class SearchResults(DataTable):
    """DataTable subclass showing search results with album art in the first column."""

    class TrackSelected(Message):
        """Emitted when the user selects a track from the results."""

        def __init__(self, sender: SearchResults, row: int) -> None:
            super().__init__()
            self.sender = sender
            self.row = row

    class LoadMore(Message):
        """Emitted when the user scrolls to the bottom of results."""

        bubble = True

    def __init__(self, widget_id: str = "search-results") -> None:
        """Initialize the search results widget."""
        super().__init__(id=widget_id)
        self._row_count: int = 0
        self._max_rows: int = 0
        self.cursor_type: str = "row"
        self.show_cursor: bool = True
        self.add_column("Art", width=16)
        self.add_columns("Title", "Artist", "Album", "Duration")
        self._render_generation: int = 0
        # Cache for stripped bgcolor styles to avoid repeated string ops.
        self._stripped_styles: dict[int, Style] = {}
        # Threshold (in rows) from the bottom to trigger loading more.
        self._load_more_threshold: int = 5
        # Cell height for rows (must match height=8 used in add_row calls).
        self._row_height: int = 8

    async def _on_click(self, event: Click) -> None:
        """Handle clicks: emit TrackSelected for valid rows."""
        meta = event.style.meta
        if not meta or meta.get("row", -1) < 0:
            return
        self.post_message(self.TrackSelected(self, int(meta["row"])))
        event.stop()

    def _check_load_more(self, old_value: float, new_value: float) -> None:
        """Check if near the bottom of scrollable content and post LoadMore.

        Called from ``watch_scroll_y`` whenever the scroll position changes.
        Only emits LoadMore when the user just entered the "near bottom" zone
        (i.e. old was outside, new is inside), so repeated calls don't trigger
        duplicate loads.
        """
        if not self.rows or self._row_count == 0:
            return
        max_scroll_y = self.max_scroll_y
        # Threshold in pixels: number of rows × row height.
        threshold_pixels = self._load_more_threshold * self._row_height
        # Distance remaining to the bottom of scrollable content (in pixels).
        remaining = max_scroll_y - new_value
        was_far = max_scroll_y - old_value > threshold_pixels
        is_near = remaining <= threshold_pixels
        if was_far and is_near and remaining >= 0:
            self.post_message(self.LoadMore())

    def _on_mouse_move(self, event: MouseMove) -> None:
        """Hide cursor and hover style for the album-art column."""
        metadata = event.style.meta
        if metadata and metadata.get("column") == 0:
            self.cursor_type = "none"
            self._set_hover_cursor(False)
            return
        self.cursor_type = "row"
        super()._on_mouse_move(event)

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        """Called whenever the DataTable's vertical scroll position changes."""
        # Preserve DataTable's original scrollbar update behavior.
        super().watch_scroll_y(old_value, new_value)
        self._check_load_more(old_value, new_value)

    def _scroll_to(
        self,
        x: float | None = None,
        y: float | None = None,
        *,
        animate: bool = True,
        speed: float | None = None,
        duration: float | None = None,
        easing: str = "ease_out_quad",
        force: bool = False,
        on_complete: object | None = None,
    ) -> bool:
        """Override to detect when scrolling near the bottom."""
        scrolled = super()._scroll_to(
            x, y,
            animate=animate,
            speed=speed,
            duration=duration,
            easing=easing,
            force=force,
            on_complete=on_complete,
        )
        # After any scroll, check if we're now near the bottom.
        if scrolled:
            self._check_load_more(
                self.scroll_y,
                y if y is not None else self.scroll_y,
            )
        return scrolled

    def _on_mouse_scroll_down(self, event: "MouseScrollDown") -> None:
        """Detect scrolling via mouse wheel."""
        old_scroll_y = self.scroll_y
        super()._on_mouse_scroll_down(event)
        self._check_load_more(old_scroll_y, self.scroll_y)

    def _on_mouse_scroll_up(self, event: "MouseScrollUp") -> None:
        """Detect scrolling via mouse wheel (up = scrolling content down)."""
        old_scroll_y = self.scroll_y
        super()._on_mouse_scroll_up(event)
        self._check_load_more(old_scroll_y, self.scroll_y)

    def _render_cell(
        self,
        row_index: int,
        column_index: int,
        base_style: "Style",
        width: int,
        cursor: bool = False,
        hover: bool = False,
    ) -> SegmentLines:
        """Override to disable hover and selection styling for the album-art column."""
        if column_index == 0:
            hover = False
            cursor = False
            # Strip the selection background so the album art
            # doesn't get covered with a white/orange overlay.
            if self._is_row_selected(row_index) and base_style.bgcolor is not None:
                bg_key = id(base_style)
                stripped = self._stripped_styles.get(bg_key)
                if stripped is None:
                    stripped = self._strip_bgcolor(base_style)
                    if len(self._stripped_styles) < 64:
                        self._stripped_styles[bg_key] = stripped
                base_style = stripped
        return super()._render_cell(
            row_index, column_index, base_style, width, cursor, hover
        )

    def _is_row_selected(self, row_index: int) -> bool:
        """Return True if *row_index* is the currently selected row."""
        cursor = self.cursor_coordinate
        if cursor is None:
            return False
        if self.cursor_type in ("row", "cell"):
            return cursor.row == row_index
        return False

    def _strip_bgcolor(self, style: "Style") -> "Style":
        """Return a copy of *style* with the background color removed."""
        s = str(style)
        on_pos = s.find(" on ")
        if on_pos != -1:
            s = s[:on_pos]
        return Style.parse(s) if s else _NULL_STYLE

    def show_loading(self) -> None:
        """Display a loading indicator."""
        self.clear()
        self.add_row("", "Searching...", "", "", "", height=1)

    def show_error(self, error: str) -> None:
        """Display an error message."""
        self.clear()
        self.add_row("", f"Error: {error}", "", "", "", height=1)

    def show_results(self, tracks: list[Track]) -> None:
        """Display search results, rendering album art asynchronously."""
        self._render_generation += 1
        generation = self._render_generation
        self.clear()
        if not tracks:
            self.add_row("", "No songs found", "", "", "")
            return
        for index, track in enumerate(tracks):
            self.add_row(
                "",
                track.title,
                track.artist,
                track.album,
                str(timedelta(milliseconds=track.duration_ms)),
                height=8,
            )
            if track.image_path and not track.image_path.startswith("Unknown"):
                self.run_worker(
                    partial(self._render_art, generation, index, track.image_path),
                    name=f"artwork-{generation}-{index}",
                    group="artwork",
                    thread=True,
                )
        self._max_rows = self._row_count

    def append_results(self, tracks: list[Track]) -> list[Track] | None:
        """Append more results without clearing existing rows.

        Returns the full list of track IDs seen so far (for deduplication),
        or ``None`` if the table was cleared.

        Args:
            tracks: Tracks to append.

        Returns:
            A set of provider IDs seen so far, for deduplication on next append.
        """
        self._render_generation += 1
        generation = self._render_generation
        existing_ids: set[str] = set()
        start_row = self._row_count
        for idx, track in enumerate(tracks):
            if track.provider_id:
                existing_ids.add(track.provider_id)
            actual_row = start_row + idx
            self.add_row(
                "",
                track.title,
                track.artist,
                track.album,
                str(timedelta(milliseconds=track.duration_ms)),
                height=8,
            )
            if track.image_path and not track.image_path.startswith("Unknown"):
                self.run_worker(
                    partial(self._render_art, generation, actual_row, track.image_path),
                    name=f"artwork-{generation}-{actual_row}",
                    group="artwork",
                    thread=True,
                )
        self._max_rows = self._row_count
        return existing_ids

    def show_loading_more(self) -> None:
        """Display a 'loading more' row at the bottom."""
        current_rows = self._row_count
        self.add_row("", "Loading more...", "", "", "", height=1, key=str(current_rows))

    def _render_art(self, generation: int, row: int, path: str) -> tuple[int, int, str] | None:
        """Render album art for a track in a background worker."""
        try:
            result: str = downscale(path, cols=16, cell_aspect=2.0)
            return (generation, row, result)
        except (OSError, ValueError):
            return None

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle completion of an artwork rendering worker."""
        if event.state != WorkerState.SUCCESS:
            return
        result = cast("tuple[int, int, str] | None", event.worker.result)
        if result is None:
            return
        generation, row, ansi = result
        if generation != self._render_generation or not ansi:
            return
        self.update_cell_at(
            Coordinate(row, 0),
            Text.from_ansi(ansi),
        )
        self._max_rows = self._row_count