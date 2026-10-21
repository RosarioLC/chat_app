# ui/widgets/modal.py
"""Modal dialog widgets for the application."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Label


class NewPlaylistScreen(ModalScreen):
    """Modal dialog for creating a new playlist."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self) -> None:
        """Initialize the new playlist dialog."""
        super().__init__()
        self._result: str | None = None

    def compose(self) -> ComposeResult:
        """Compose the dialog layout."""
        with Vertical(id="modal-dialog"):
            yield Label("Enter playlist name:", id="modal-title")
            yield Input(placeholder="My Playlist", id="playlist-name-input")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", variant="primary", id="create-button")
                yield Button("Cancel", variant="default", id="cancel-button")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "create-button":
            name = self.query_one("#playlist-name-input", Input).value.strip()
            if name:
                self._result = name
                self.dismiss(self._result)
            else:
                self.notify("Please enter a playlist name", severity="error")
        elif event.button.id == "cancel-button":
            self.dismiss(None)

    def on_mount(self) -> None:
        """Focus the input field."""
        self.query_one("#playlist-name-input", Input).focus()


class PlaylistPickerScreen(ModalScreen):
    """Modal dialog for choosing which playlist to add a track to."""

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
        with Vertical(id="modal-dialog"):
            yield Label("Add to playlist:", id="modal-title")
            if self._playlists:
                for playlist in self._playlists:
                    yield Button(
                        playlist.name,
                        variant="primary",
                        id=f"playlist-{playlist.id}",
                    )
            else:
                yield Label("No playlists yet.", id="empty-message")
            with Horizontal(id="modal-buttons"):
                yield Button("Cancel", variant="default", id="cancel-button")
        yield Footer()

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
