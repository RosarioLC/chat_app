# ui/widgets/modal.py
"""Modal dialog widgets for the application."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Label, Static


class NewPlaylistScreen(ModalScreen):
    """Modal dialog for creating a new playlist."""

    CSS = """
    #new-playlist-container {
        background: #181818;
        border: solid #1ed760;
        width: 50;
        height: auto;
        padding: 1 2;
        margin: 1;
        layout: vertical;
        align: center middle;
    }

    #new-playlist-title {
        text-style: bold;
        color: #ffffff;
        height: 3;
        content-align: center middle;
    }

    #new-playlist-input {
        width: 100%;
        margin-top: 1;
        padding: 0 1;
        height: 3;
        color: #ffffff;
        background: #242424;
        border: round #535353;
        border-color: #535353;
    }

    #new-playlist-input:focus {
        border: round #1ed760;
        border-color: #1ed760;
    }

    #new-playlist-buttons {
        dock: bottom;
        width: 100%;
        layout: horizontal;
        margin-top: 1;
    }

    #new-playlist-buttons Button {
        width: 50%;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self) -> None:
        """Initialize the new playlist dialog."""
        super().__init__()
        self._result: str | None = None

    def compose(self) -> ComposeResult:
        """Compose the dialog layout."""
        with Container(id="new-playlist-container"):
            yield Label("Enter playlist name:", id="new-playlist-title")
            yield Input(placeholder="My Playlist", id="new-playlist-input")
            with Horizontal(id="new-playlist-buttons"):
                yield Button("Create", variant="primary", id="create-button")
                yield Button("Cancel", variant="default", id="cancel-button")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "create-button":
            name = self.query_one("#new-playlist-input", Input).value.strip()
            if name:
                self._result = name
                self.dismiss(self._result)
            else:
                self.notify("Please enter a playlist name", severity="error")
        elif event.button.id == "cancel-button":
            self.dismiss(None)

    def on_mount(self) -> None:
        """Focus the input field."""
        self.call_later(self._focus_input)

    def _focus_input(self) -> None:
        """Focus the input field after DOM is ready."""
        input_widget = self.query_one("#new-playlist-input", Input)
        input_widget.focus()

    def on_key(self, event) -> None:
        """Handle Enter key to submit."""
        if event.key == "enter":
            self.on_button_pressed(
                Button.Pressed(self.query_one("#create-button", Button))
            )


class PlaylistPickerScreen(ModalScreen):
    """Modal dialog for choosing which playlist to add a track to."""

    CSS = """
    #playlist-picker-container {
        background: $surface;
        border: solid $primary;
        width: 50;
        height: auto;
        padding: 1 2;
        margin: 1;
        layout: vertical;
        align: center middle;
        dock: top;
    }

    #playlist-picker-title {
        text-style: bold;
        color: $text;
        height: 3;
        content-align: center middle;
    }

    #playlist-picker-buttons {
        dock: bottom;
        width: 100%;
        layout: horizontal;
        margin-top: 1;
    }

    #playlist-picker-buttons Button {
        width: 50%;
    }

    #empty-message {
        height: 3;
        color: $text-muted;
        content-align: center middle;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, playlists: list) -> None:
        """Initialize the playlist picker.

        Args:
            playlists: List of playlist objects with 'id' and 'name' attributes.
        """
        super().__init__()
        self._playlists = playlists
        self._result: int | None = None

    def compose(self) -> ComposeResult:
        """Compose the picker layout."""
        with Container(id="playlist-picker-container"):
            yield Label("Add to playlist:", id="playlist-picker-title")
            if self._playlists:
                for playlist in self._playlists:
                    yield Button(
                        playlist.name,
                        variant="primary",
                        id=f"playlist-{playlist.id}",
                    )
            else:
                yield Static("No playlists yet.", id="empty-message")
            with Horizontal(id="playlist-picker-buttons"):
                yield Button("Cancel", variant="default", id="cancel-button")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "cancel-button":
            self.dismiss(None)
        elif event.button.id and event.button.id.startswith("playlist-"):
            playlist_id = int(event.button.id.removeprefix("playlist-"))
            self._result = playlist_id
            self.dismiss(self._result)

    def on_mount(self) -> None:
        """Focus the first playlist button if available."""
        if self._playlists:
            first_btn = self.query_one("#playlist-0", Button)
            if first_btn:
                first_btn.focus()

