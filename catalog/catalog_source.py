from typing import Protocol

from model.track import Track


class CatalogSource(Protocol):
    """Interface for music catalog providers (YouTube Music, etc.).

    Implementations must provide a :meth:`search` method that returns
    a list of :class:`~model.track.Track` objects matching the query.
    """

    def search(self, query: str) -> list[Track]:
        """Search the catalog and return matching tracks.

        Args:
            query: The search query string.

        Returns:
            A list of tracks matching the query. May be empty.
        """
        ...
