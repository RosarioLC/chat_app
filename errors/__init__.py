# errors/__init__.py
from .exceptions import (
    MusicError,
    StreamError,
    LyricsError,
    PlaybackError,
    PlaylistError,
    CatalogError,
    AuthenticationError,
    NotFoundError,
)

__all__ = [
    "MusicError",
    "StreamError",
    "LyricsError",
    "PlaybackError",
    "PlaylistError",
    "CatalogError",
    "AuthenticationError",
    "NotFoundError",
]
