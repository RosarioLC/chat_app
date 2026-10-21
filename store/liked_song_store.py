from model.track import Track
from store.database import Database


class LikedSongStore:
    """Persists liked songs to the database."""

    def __init__(self, db: Database) -> None:
        """Initialize the store.

        Args:
            db: Database connection.
        """
        self._db: Database = db

    def add(self, track: Track) -> None:
        """Add a track to the liked songs collection.

        Args:
            track: The track to like.
        """
        self._db.execute(
            "INSERT INTO liked_songs (track_id) VALUES (?)", (track.id,)
        )
        self._db.commit()

    def remove(self, track_id: int) -> None:
        """Remove a track from the liked songs collection.

        Args:
            track_id: ID of the track to unlike.
        """
        self._db.execute(
            "DELETE FROM liked_songs WHERE track_id = ?", (track_id,)
        )
        self._db.commit()

    def list_ids(self) -> list[int]:
        """Return a list of all liked track IDs, ordered by ID.

        Returns:
            List of track ID integers.
        """
        rows = self._db.fetchall(
            "SELECT track_id FROM liked_songs ORDER BY track_id"
        )
        return [int(row["track_id"]) for row in rows]
