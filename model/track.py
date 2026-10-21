"""Track model representing a single music track."""

from __future__ import annotations

from dataclasses import dataclass, replace as _dc_replace

# Module-level constants for default values.
# Using constants instead of a shared dict avoids accidental mutation.
_DEFAULT_TITLE: str = "Unknown Title"
_DEFAULT_ARTIST: str = "Unknown Artist"
_DEFAULT_ALBUM: str = "Unknown Album"
_DEFAULT_IMAGE_PATH: str = "Unknown Image Path"
_DEFAULT_LYRICS_PATH: str = "Unknown Lyrics Path"
_DEFAULT_URL: str = ""


@dataclass(slots=True, frozen=True)
class Track:
    """Represents a single music track with metadata.

    Tracks are effectively immutable. Fields are validated and normalized
    at construction time.
    """

    id: int
    title: str = _DEFAULT_TITLE
    artist: str = _DEFAULT_ARTIST
    album: str = _DEFAULT_ALBUM
    duration_ms: int = 0
    image_path: str = _DEFAULT_IMAGE_PATH
    lyrics_path: str = _DEFAULT_LYRICS_PATH
    url: str = _DEFAULT_URL
    provider_id: str = ""

    def __post_init__(self) -> None:
        """Normalize empty / whitespace-only fields to defaults.

        Uses object.__setattr__ because the dataclass uses slots (not frozen).
        """
        # Inline the common fields for speed.
        if not self.title or not self.title.strip():
            object.__setattr__(self, "title", _DEFAULT_TITLE)
        if not self.artist or not self.artist.strip():
            object.__setattr__(self, "artist", _DEFAULT_ARTIST)
        if not self.album or not self.album.strip():
            object.__setattr__(self, "album", _DEFAULT_ALBUM)
        if not self.image_path or not self.image_path.strip():
            object.__setattr__(self, "image_path", _DEFAULT_IMAGE_PATH)
        if not self.lyrics_path or not self.lyrics_path.strip():
            object.__setattr__(self, "lyrics_path", _DEFAULT_LYRICS_PATH)
        if not self.url or not self.url.strip():
            object.__setattr__(self, "url", _DEFAULT_URL)
        # Ensure duration is non-negative.
        if self.duration_ms < 0:
            object.__setattr__(self, "duration_ms", 0)

    def to_dict(self) -> dict[str, object]:
        """Serialize the track to a plain dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "artist": self.artist,
            "album": self.album,
            "duration_ms": self.duration_ms,
            "lyrics_path": self.lyrics_path,
            "url": self.url,
            "provider_id": self.provider_id,
        }

    def __hash__(self) -> int:
        """Hash based on track ID for use in sets / dicts."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Tracks are equal if their IDs match."""
        if not isinstance(other, Track):
            return NotImplemented
        return self.id == other.id

    def replace(self, **changes: object) -> "Track":
        """Return a new Track with the given fields replaced.

        Args:
            **changes: Fields to replace (e.g. ``title="New"``).

        Returns:
            A new :class:`Track` instance with updated fields.
        """
        return _dc_replace(self, **changes)  # type: ignore[call-overload]
