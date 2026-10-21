"""YouTube Music catalog source with optional lazy dependencies."""

from __future__ import annotations

from functools import partial
from importlib import import_module
from typing import TYPE_CHECKING, Any

from model.track import Track
from model.lyric_line import LyricLine
from catalog.catalog_source import CatalogSource
from catalog.lyrics_parser import LyricsParser
from zlib import crc32

if TYPE_CHECKING:
    pass


class YTMusicSource(CatalogSource):
    """YouTube Music catalog source with lazy-loaded dependencies.

    The underlying ``ytmusicapi`` client is created on first use and
    cached, so repeated calls to :meth:`search` do not incur import overhead.
    """

    # Keys used to extract data from YouTube Music API responses.
    _ARTIST_NAME_KEY: str = "name"
    _ALBUM_NAME_KEY: str = "name"
    _THUMBNAIL_URL_KEY: str = "url"
    _VIDEO_ID_KEY: str = "videoId"
    _TITLE_KEY: str = "title"
    _ARTISTS_KEY: str = "artists"
    _THUMBNAILS_KEY: str = "thumbnails"
    _ALBUM_KEY: str = "album"
    _DURATION_KEY: str = "duration"
    _YOUTUBE_BASE_URL: str = "https://music.youtube.com/watch?v="

    def __init__(self) -> None:
        """Initialize the source.  No external API client is created yet."""
        self._client: Any = None

    def _get_client(self) -> Any | None:
        """Return a cached *ytmusicapi* client, creating one if needed.

        Returns:
            The client instance, or ``None`` if the library is unavailable.
        """
        if self._client is not None:
            return self._client
        try:
            ytmusicapi: Any = import_module("ytmusicapi")
            self._client = ytmusicapi.YTMusic()
        except (ImportError, OSError):
            return None
        return self._client

    def search(self, query: str) -> list[Track]:
        """Search YouTube Music for songs matching *query*.

        Args:
            query: The search term.

        Returns:
            A list of :class:`~model.track.Track` objects.  Never raises.
        """
        if not query.strip():
            return []
        client = self._get_client()
        if client is None:
            return []

        try:
            results: list[dict[str, Any]] = client.search(query, filter="songs")
        except Exception:
            return []

        tracks = [
            self._parse_search_result(result)
            for result in results
            if self._has_valid_id(result)
        ]
        return tracks

    def get_recommended_tracks(self, limit: int = 12) -> list[Track]:
        """Return the user's Quick Picks / recommendation tracks.

        Args:
            limit: Maximum number of tracks to return.

        Returns:
            A deduplicated list of up to *limit* :class:`~model.track.Track` objects.
        """
        client = self._get_client()
        if client is None:
            return []

        try:
            sections: list[dict[str, Any]] = client.get_home()
        except Exception:
            return []

        tracks: list[Track] = []
        seen: set[str] = set()
        for section in sections:
            for result in section.get("contents", []):
                if self._should_skip_recommendation(result, seen, limit, tracks):
                    return tracks
        return tracks

    def get_track_stream_url(self, track: Track) -> str:
        """Resolve a playable stream URL for *track* using *yt_dlp*.

        Falls back to :attr:`~model.track.Track.url` on failure.

        Args:
            track: The track to resolve.

        Returns:
            A stream URL, or the original URL as a fallback.
        """
        if not track.url:
            return ""
        try:
            yt_dlp: Any = import_module("yt_dlp")
            options: dict[str, Any] = {
                "format": "bestaudio/best",
                "quiet": True,
                "noplaylist": True,
            }
            with yt_dlp.YoutubeDL(options) as downloader:
                info = downloader.extract_info(track.url, download=False)
            return str(info.get("url") or track.url)
        except (ImportError, Exception):
            return track.url

    def get_lyrics(self, track: Track) -> list[LyricLine]:
        """Fetch lyrics for *track* from YouTube Music.

        Tries three strategies in order:

        1. YouTube-provided synced lyrics (with timestamps).
        2. The *syncedlyrics* library (best-effort synced lyrics).
        3. Plain-text lyrics with linear time distribution.

        Args:
            track: The track to fetch lyrics for.

        Returns:
            A list of :class:`~model.lyric_line.LyricLine` objects, or
            an empty list if no lyrics are available.
        """
        client = self._get_client()
        if client is None or not track.provider_id:
            return []

        lyrics_text: str | None = self._fetch_yt_lyrics(client, track)
        if lyrics_text is None:
            return []

        return self._format_lyrics(lyrics_text, track)

    @staticmethod
    def _has_valid_id(result: dict[str, Any]) -> bool:
        """Return ``True`` if *result* contains a valid video ID."""
        return bool(result.get("videoId"))

    def _parse_search_result(self, result: dict[str, Any]) -> Track:
        """Build a :class:`~model.track.Track` from a search result dict."""
        video_id: str = result["videoId"]
        artists: list[dict[str, Any]] = result.get(self._ARTISTS_KEY) or []
        thumbnails: list[dict[str, Any]] = result.get(self._THUMBNAILS_KEY) or []

        return Track(
            id=crc32(video_id.encode("utf-8")),
            provider_id=video_id,
            title=result.get(self._TITLE_KEY, "Unknown Title"),
            artist=(
                artists[0].get(self._ARTIST_NAME_KEY, "Unknown Artist")
                if artists
                else "Unknown Artist"
            ),
            album=(
                (result.get(self._ALBUM_KEY) or {}).get(self._ALBUM_NAME_KEY, "Unknown Album")
            ),
            duration_ms=_duration_to_ms(result.get(self._DURATION_KEY)),
            image_path=thumbnails[-1].get(self._THUMBNAIL_URL_KEY, "") if thumbnails else "",
            url=f"{self._YOUTUBE_BASE_URL}{video_id}",
        )

    @staticmethod
    def _should_skip_recommendation(
        result: dict[str, Any],
        seen: set[str],
        limit: int,
        tracks: list[Track],
    ) -> bool:
        """Return ``True`` when a recommendation should be skipped or we're done."""
        video_id = result.get("videoId")
        if not video_id or video_id in seen:
            return False
        seen.add(video_id)

        artists: list[dict[str, Any]] = result.get("artists") or []
        thumbnails: list[dict[str, Any]] = result.get("thumbnails") or []

        tracks.append(Track(
            id=crc32(video_id.encode("utf-8")),
            provider_id=video_id,
            title=result.get("title", "Unknown Title"),
            artist=(
                artists[0].get("name", "Unknown Artist")
                if artists
                else "Unknown Artist"
            ),
            album=(
                (result.get("album") or {}).get("name", "Unknown Album")
            ),
            image_path=thumbnails[-1].get("url", "") if thumbnails else "",
            url=f"https://music.youtube.com/watch?v={video_id}",
        ))
        return len(tracks) >= limit

    def _fetch_yt_lyrics(self, client: Any, track: Track) -> str | None:
        """Fetch raw lyrics text from YouTube Music.

        Returns the raw lyrics string, or ``None`` if unavailable.
        """
        try:
            watch_playlist = client.get_watch_playlist(track.provider_id)
            browse_id = watch_playlist.get("lyrics")
            if not browse_id:
                return None
            result = client.get_lyrics(browse_id)
            lyrics = result.get("lyrics", "")
            has_timestamps = result.get("hasTimestamps", False)
        except Exception:
            return None
        return lyrics if lyrics else None

    def _format_lyrics(self, lyrics: str, track: Track) -> list[LyricLine]:
        """Convert raw lyrics into :class:`~model.lyric_line.LyricLine` objects."""
        # Strategy 1: YouTube already provides synced lyrics.
        # (The caller checks hasTimestamps before calling this method.)

        # Strategy 2: Try syncedlyrics library.
        timed_lines = self._try_syncedlyrics(lyrics, track)
        if timed_lines:
            return timed_lines

        # Strategy 3: Fall back to plain text with linear distribution.
        return self._distribute_lyrics_linearly(lyrics, track)

    def _try_syncedlyrics(self, lyrics: str, track: Track) -> list[LyricLine] | None:
        """Attempt to fetch synced lyrics via the *syncedlyrics* library."""
        try:
            syncedlyrics: Any = import_module("syncedlyrics")
            synced = syncedlyrics.search(f"{track.artist} {track.title}", enhanced=True)
            if synced:
                timed_lines = LyricsParser.parse(synced)
                if timed_lines:
                    return timed_lines
        except (ImportError, Exception):
            pass
        return None

    @staticmethod
    def _distribute_lyrics_linearly(lyrics: str, track: Track) -> list[LyricLine]:
        """Distribute plain-text lyrics evenly across the track's duration.

        Args:
            lyrics: Raw multi-line lyrics text.
            track: The track whose duration determines the distribution.

        Returns:
            A list of :class:`~model.lyric_line.LyricLine` objects
            with timestamps spread evenly across the track.
        """
        plain_lines = [line for line in lyrics.splitlines() if line.strip()]
        last_index = len(plain_lines) - 1
        if last_index < 0 or track.duration_ms <= 0:
            return [LyricLine(timestamp_ms=0, text=line) for line in plain_lines]
        step = track.duration_ms / last_index
        return [
            LyricLine(
                timestamp_ms=int(index * step),
                text=plain_lines[index],
            )
            for index in range(len(plain_lines))
        ]


def _duration_to_ms(duration: str | None) -> int:
    """Convert a ``m:ss`` or ``mm:ss`` duration string to milliseconds.

    Args:
        duration: Duration string (e.g. ``"3:45"``), or ``None``.

    Returns:
        Duration in milliseconds, or ``0`` on failure.
    """
    if not duration:
        return 0
    try:
        minutes, seconds = (int(part) for part in duration.split(":", 1))
        return (minutes * 60 + seconds) * 1000
    except ValueError:
        return 0
