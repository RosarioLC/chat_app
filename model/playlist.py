"""Playlist model containing a sequence of tracks."""

from model.track import Track
from typing import Iterator


class Playlist():
    """A collection of tracks with indexing and navigation helpers.

    Maintains both a list (for ordered iteration) and a set (for O(1) membership),
    keeping them in sync during mutations.
    """

    def __init__(self, id: int, name: str | None, songs: list[Track] | None, position: int = 0) -> None:
        """Initialize a new Playlist.

        Args:
            id: Unique identifier for the playlist.
            name: Display name; defaults to "No Name" if falsy.
            songs: Initial tracks; defaults to empty list.
            position: Initial cursor position.
        """
        self._id: int = id
        self._name: str = name.strip() if name and name.strip() else "No Name"
        self._songs: list[Track] = list(songs) if songs else []
        self._position: int = position
        # Set for O(1) membership testing.
        self._song_ids: set[int] = {t.id for t in self._songs}

    @property
    def id(self) -> int:
        """Unique identifier for the playlist."""
        return self._id

    @property
    def name(self) -> str:
        """Display name of the playlist."""
        return self._name

    @name.setter
    def name(self, value: str | None) -> None:
        """Update the playlist name, stripping whitespace."""
        if value and value.strip():
            self._name = value.strip()

    @property
    def songs(self) -> list[Track]:
        """The tracks in this playlist."""
        return self._songs

    @property
    def position(self) -> int:
        """Current cursor position within the playlist."""
        return self._position

    def __iter__(self) -> Iterator[Track]:
        """Iterate over the tracks in the playlist."""
        return iter(self._songs)

    def __len__(self) -> int:
        """Return the number of tracks in the playlist."""
        return len(self._songs)

    def __contains__(self, track: object) -> bool:
        """Check whether a track is in the playlist (O(1) lookup)."""
        if isinstance(track, Track):
            return track.id in self._song_ids
        return track in self._songs

    def add_song(self, track: Track) -> None:
        """Add a track to the end of the playlist.

        Args:
            track: The track to add.

        Raises:
            ValueError: If track is None or already in the playlist.
        """
        if track is None:
            raise ValueError("Track is null")
        if track.id in self._song_ids:
            raise ValueError("Track is already in the collection")
        self._songs.append(track)
        self._song_ids.add(track.id)
        self._position += 1

    def remove_song(self, track: Track) -> None:
        """Remove a track from the playlist.

        Args:
            track: The track to remove.

        Raises:
            ValueError: If track is None or not in the playlist.
        """
        if track is None:
            raise ValueError("Track is null")
        if track.id not in self._song_ids:
            raise ValueError("Track is not in the playlist")
        self._songs.remove(track)
        self._song_ids.discard(track.id)
        if not self._songs:
            self._position = 0

    def next_song(self, track: Track) -> Track:
        """Get the track that follows the given track.

        Args:
            track: The current track.

        Returns:
            The next track in the playlist.

        Raises:
            IndexError: If the track is the last in the playlist.
        """
        index = self._index_of(track)
        if index + 1 >= len(self._songs):
            raise IndexError("No next song")
        return self._songs[index + 1]

    def previous_song(self, track: Track) -> Track:
        """Get the track that precedes the given track.

        Args:
            track: The current track.

        Returns:
            The previous track in the playlist.

        Raises:
            IndexError: If the track is the first in the playlist.
        """
        index = self._index_of(track)
        if index <= 0:
            raise IndexError("No previous song")
        return self._songs[index - 1]

    def _index_of(self, track: Track) -> int:
        """Get the zero-based index of a track in the playlist.

        Args:
            track: The track to locate.

        Returns:
            The index of the track.

        Raises:
            InvalidMusicCollectionException: If track is None or not found.
        """
        if track is None or track not in self._songs:
            raise ValueError("Track is not in the playlist")
        return self._songs.index(track)
