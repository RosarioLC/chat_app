from model.track import Track


class StreamResolver:
    """Resolve track metadata into playable stream URLs."""

    def resolve(self, track: Track) -> str:
        """Return the stream URL for a track.

        Args:
            track: The track to resolve.

        Returns:
            The track's URL. Returns an empty string if unavailable.
        """
        return track.url
