# MusicTUI

A terminal-based music player built with [Textual](https://textual.textualize.io/) that streams from YouTube Music, displays synchronized lyrics, and renders album art directly in the terminal using ANSI half-block characters.

```
+---------------------------------------------------+
│  🔍 Search...                                     │
│                                                   │
│  HOME                                             │
│  ┌────┬──────────────────┬───────┬───────┬───────┐│
│  │ 🎵 │ Song Title       │ Artist│ Album │ 3:45  ││
│  │ 🎵 │ Another Song     │ Band  │ LP    │ 4:12  ││
│  │    │ ... (scrollable) │       │       │       ││
│  └────┴──────────────────┴───────┴───────┴───────┘│
│                        ┌──────────────┐            │
│                        │ Next: Track  │            │
│                        └──────────────┘            │
│  ▶ ⏸ ⏭  1:23 / 3:45            🔊 80%  🖥️ 📜     │
│  [H]ome  [S]earch  [L]ibrary  [F]ullscreen  [Q]uit │
+---------------------------------------------------+
```

## Features

- **🎧 Real-time playback** — Streams directly from YouTube Music using `ytmusicapi`, with VLC as the audio backend
- **📜 Synchronized lyrics** — Fetches lyrics via YouTube Music and the `syncedlyrics` library, with timestamp-based highlighting as the song plays
- **🎨 Terminal-rendered album art** — Uses NumPy and Pillow to downscale images to ANSI half-block colour characters, rendered in real-time
- **♾️ Infinite scroll** — Edge-triggered lazy loading on all result tables — loads more tracks only when the user scrolls within 5 rows of the bottom
- **📋 Playlist management** — Create, rename, and delete playlists backed by a SQLite database
- **🔀 Smart queue** — Skip, shuffle, history-aware back navigation, and repeat modes (OFF / ALL / ONE)
- **🖥️ Fullscreen album art** — Press `F` to enter fullscreen mode with the album art rendered at full terminal resolution
- **⚡ Background workers** — Artwork rendering, stream resolution, and lyrics fetching all happen in threaded workers with generation-based cancellation to avoid race conditions

## Architecture

```
music/
├── main.py                          # Application entry point
├── pyproject.toml                   # Dependencies & project metadata
├── model/
│   ├── track.py                     # Immutable Track dataclass (slots=True, frozen=True)
│   ├── lyric_line.py                # Timed lyric line model
│   └── repeat_mode.py               # Enum: OFF → ALL → ONE
├── catalog/
│   ├── ytmusic_source.py            # YouTube Music API client (lazy-loaded)
│   ├── downscaler.py                # Image → ANSI half-block renderer (NumPy + Pillow)
│   ├── lyrics_parser.py             # Parses synced lyrics timestamps
│   ├── catalog_source.py            # Abstract base for catalog providers
│   └── track_cache.py               # LRU cache for lyrics and stream URLs
├── playback/
│   ├── player.py                    # High-level playback controller
│   ├── vlc_backend.py               # VLC media library wrapper
│   └── music_queue.py               # Queue with history, repeat, and shuffle
├── store/
│   ├── database.py                  # SQLite connection wrapper
│   ├── playlist_store.py            # CRUD operations for playlists
│   └── liked_songs_store.py         # Liked songs persistence
└── ui/
    ├── app.py                       # MusicTUI application (screen nav, workers)
    ├── style.tcss                   # Textual CSS theme (dark, Spotify-inspired)
    ├── screens/
    │   ├── home_screen.py           # Recommendations + infinite scroll
    │   ├── search_screen.py         # Search with deduplication
    │   ├── library_screen.py        # Browse by artist/album
    │   ├── playlist_screen.py       # Playlist CRUD
    │   ├── lyrics_screen.py         # Synchronized lyrics display
    │   └── fullscreen_screen.py     # Fullscreen album art overlay
    └── widgets/
        ├── search_bar.py            # Search input with label
        ├── search_result.py         # DataTable subclass with artwork + scroll detection
        ├── now_playing_bar.py       # Playback state + progress + volume
        ├── player_controls.py       # Play/pause/next/prev buttons
        ├── queue_panel.py           # Upcoming tracks list
        ├── lyrics_panel.py          # Scrolling lyrics display
        ├── next_track_card.py       # Preview of the next track
        ├── volume_control.py        # Volume slider
        ├── track_progress.py        # Seekable progress bar
        ├── action_hints.py          # Keyboard shortcut hints
        └── sidebar.py               # Navigation sidebar
```

## Tech Stack

| Category | Technology |
|---|---|
| **TUI Framework** | Textual 0.40+ |
| **Audio Playback** | VLC (python-vlc) |
| **Music Source** | YouTube Music API (ytmusicapi) |
| **Image Rendering** | NumPy, Pillow (PIL) |
| **Lyrics Sync** | syncedlyrics |
| **Database** | SQLite (stdlib) |
| **Testing** | pytest |
| **Language** | Python 3.12+ |

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/music.git
cd music

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
source .venv/bin/activate    # macOS / Linux

# Install dependencies
pip install -e ".[dev]"

# Run the app
python -m main
```

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `H` | Go to Home (recommendations) |
| `S` | Go to Search |
| `L` | Go to Library |
| `F` | Toggle fullscreen album art |
| `Q` | Quit |
| `Up/Down` | Navigate track list |
| `Enter` | Play selected track |

## What's Next

- [ ] Local file playback (MP3, FLAC)
- [ ] Spotify integration as an alternative source
- [ ] Crossfade between tracks
- [ ] Custom themes / color schemes
- [ ] Web UI option

## License

MIT
