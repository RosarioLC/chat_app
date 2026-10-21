from enum import Enum


class RepeatMode(Enum):
    """Enum defining the available repeat modes for playback."""
    OFF = 0
    ALL = 1
    ONE = 2

    def next_mode(self) -> "RepeatMode":
        """Return the next repeat mode in the cycle."""
        return RepeatMode((self.value + 1) % 3)
