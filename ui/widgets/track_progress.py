from ui.widgets.slider import Slider

# Cached reference to avoid repeated getattr calls.
_PLAYER_GETTER: str = "_player"


class TrackProgress(Slider):
    """A horizontal slider that mirrors playback position.

    Responds to user interaction by seeking the player to the selected position.
    """

    def on_mount(self) -> None:
        """Apply styling and initialise value/range."""
        self.add_class("track-progress")
        self.maximum = 1
        self.value = 0

    def on_slider_updated(self, event: Slider.Updated) -> None:
        """Seek the player when the user drags the slider."""
        app = self.app
        if app is not None:
            player = getattr(app, _PLAYER_GETTER, None)
            if player is not None:
                player.seek(int(event.value))
