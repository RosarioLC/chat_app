from textual.widgets import Static, Label, DataTable
from textual.app import ComposeResult
from model.track import Track


class QueuePanel(Static):
    """Displays the upcoming tracks in the queue."""

    def __init__(self) -> None:
        """Initialize the queue panel."""
        super().__init__(id="queue-panel")
        self._table_ref: DataTable | None = None

    def compose(self) -> ComposeResult:
        """Compose the queue panel layout."""
        yield Label("Up Next")
        yield DataTable(id="queue-tracks")

    def on_mount(self) -> None:
        """Cache the table reference."""
        try:
            self._table_ref = self.query_one("#queue-tracks", DataTable)
        except Exception:
            pass

    def update_tracks(self, tracks: list[Track]) -> None:
        """Update the displayed tracks.

        Args:
            tracks: List of upcoming tracks.
        """
        table = self._table_ref
        if table is None:
            return
        table.clear(columns=False)
        if not table.columns:
            table.add_columns("Title", "Artist")
        for track in tracks:
            table.add_row(track.title, track.artist)
