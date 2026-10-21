from textual.app import ComposeResult
from textual.widgets import Static

from ui.widgets.search_input import SearchInput


class SearchBar(Static):
    """Horizontal bar with a SEARCH label and input."""

    def __init__(self) -> None:
        """Initialize the search bar."""
        super().__init__(id="search-bar")

    def compose(self) -> ComposeResult:
        """Compose the search label and input field."""
        yield Static("SEARCH", id="search-label")
        yield SearchInput()
