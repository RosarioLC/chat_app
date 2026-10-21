from textual.widgets import Static, Button
from textual.app import ComposeResult

# Button labels for transport controls.
_BTN_PREV: str = "<<"
_BTN_PLAY: str = "▶"
_BTN_NEXT: str = ">>"

# Cached attribute names.
_PLAYER_ATTR: str = "_player"


class PlayerControls(Static):
    """Transport controls: previous, play/pause, and next."""

    def __init__(self) -> None:
        """Initialize the player controls."""
        super().__init__(id="player-controls")
        self._player_ref: object | None = None

    def compose(self) -> ComposeResult:
        """Compose the transport buttons."""
        yield Static("", classes="control-spacer")
        yield Button(_BTN_PREV, id="prev")
        yield Button(_BTN_PLAY, id="play-pause")
        yield Button(_BTN_NEXT, id="next")
        yield Static("", classes="control-spacer")

    def on_mount(self) -> None:
        """Cache the player reference once."""
        if self.app and hasattr(self.app, _PLAYER_ATTR):
            self._player_ref = getattr(self.app, _PLAYER_ATTR)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route button presses to the player."""
        player = self._player_ref
        if player is None:
            return
        match event.button.id:
            case "prev":
                player.play_previous()
            case "play-pause":
                player.toggle_play_pause()
            case "next":
                player.play_next()
            case _:
                pass  # Ignore unknown button IDs.
