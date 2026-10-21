# errors/exceptions.py
"""Custom exception hierarchy for MusicTUI."""


class MusicError(Exception):
    """Base exception for all MusicTUI errors."""

    def __init__(self, message: str = "An unexpected error occurred"):
        self.message = message
        super().__init__(self.message)


class StreamError(MusicError):
    """Raised when stream resolution or playback fails."""

    def __init__(self, message: str = "Failed to resolve or play stream"):
        self.message = message
        super().__init__(self.message)


class LyricsError(MusicError):
    """Raised when lyrics fetching or parsing fails."""

    def __init__(self, message: str = "Failed to fetch or parse lyrics"):
        self.message = message
        super().__init__(self.message)


class PlaybackError(MusicError):
    """Raised when playback state or controls fail."""

    def __init__(self, message: str = "Playback error occurred"):
        self.message = message
        super().__init__(self.message)


class PlaylistError(MusicError):
    """Raised when playlist operations fail."""

    def __init__(self, message: str = "Playlist operation failed"):
        self.message = message
        super().__init__(self.message)


class CatalogError(MusicError):
    """Raised when catalog/source operations fail."""

    def __init__(self, message: str = "Catalog operation failed"):
        self.message = message
        super().__init__(self.message)


class AuthenticationError(MusicError):
    """Raised when authentication or API access fails."""

    def __init__(self, message: str = "Authentication failed"):
        self.message = message
        super().__init__(self.message)


class NotFoundError(MusicError):
    """Raised when a requested resource is not found."""

    def __init__(self, message: str = "Resource not found"):
        self.message = message
        super().__init__(self.message)
