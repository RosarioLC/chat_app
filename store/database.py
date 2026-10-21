from __future__ import annotations

import sqlite3
from pathlib import Path


class Database:
    """SQLite database wrapper for persistent storage.

    Creates tables for ``liked_songs`` and ``playlists`` on first connection.
    Supports use as a context manager for automatic cleanup.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str) -> None:
        """Initialize the database connection and create tables if needed."""
        self._db_path: Path = Path(db_path)
        self._connect()

    def _connect(self) -> None:
        """Open the SQLite connection and create default tables."""
        self._conn: sqlite3.Connection = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS liked_songs "
            "(track_id INTEGER PRIMARY KEY)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS playlists "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"
        )
        self._conn.commit()

    def __enter__(self) -> Database:
        """Return self for use as a context manager."""
        return self

    def __exit__(self, *args: object) -> None:
        """Close the database connection."""
        self.close()

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute *query* with *params* and return the cursor.

        Args:
            query: SQL query string.
            params: Parameter tuple for query substitution.

        Returns:
            The SQLite cursor after execution.
        """
        cursor = self._conn.cursor()
        cursor.execute(query, params)
        return cursor

    def commit(self) -> None:
        """Commit the current transaction."""
        self._conn.commit()

    def fetchall(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute *query* and return all rows.

        Args:
            query: SQL query string.
            params: Parameter tuple for query substitution.

        Returns:
            A list of :class:`sqlite3.Row` objects.
        """
        return self.execute(query, params).fetchall()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
