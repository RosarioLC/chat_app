from model.playlist import Playlist
from model.track import Track
from store.database import Database


class PlaylistStore:
    """Persists playlists to the database."""

    def __init__(self, db: Database) -> None:
        """Initialize the store.

        Args:
            db: Database connection.
        """
        self._db: Database = db

    def create(self, name: str) -> Playlist:
        """Create a new playlist and return it.

        Args:
            name: Display name for the playlist.

        Returns:
            A :class:`~model.playlist.Playlist` with the given name.

        Raises:
            RuntimeError: If the database fails to return the new playlist ID.
        """
        cursor = self._db.execute(
            "INSERT INTO playlists (name) VALUES (?)", (name,)
        )
        self._db.commit()
        playlist_id = cursor.lastrowid
        if playlist_id is None:
            raise RuntimeError(
                "Database did not return the new playlist ID"
            )
        return Playlist(id=playlist_id, name=name, songs=[])

    def delete(self, playlist_id: int) -> None:
        """Delete a playlist by ID.

        Args:
            playlist_id: ID of the playlist to delete.
        """
        self._db.execute(
            "DELETE FROM playlists WHERE id = ?", (playlist_id,)
        )
        self._db.commit()

    def list(self) -> list[Playlist]:
        """Return all playlists ordered by name.

        Returns:
            List of :class:`~model.playlist.Playlist` objects.
        """
        rows = self._db.fetchall(
            "SELECT id, name FROM playlists ORDER BY name"
        )
        return [
            Playlist(id=row["id"], name=row["name"], songs=[])
            for row in rows
        ]
