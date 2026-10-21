from textual.app import ComposeResult
from textual.widgets import Static

from ui.widgets.track_progress import TrackProgress


class ProgressRow(Static):
    """Row containing current time, seek slider, and duration."""

    def __init__(self) -> None:
        """Initialize the progress row."""
        super().__init__(id="progress-row")

    def compose(self) -> ComposeResult:
        """Compose the progress row layout."""
        yield Static("0:00", id="current-time")
        yield TrackProgress()
        yield Static("0:00", id="duration-time")
