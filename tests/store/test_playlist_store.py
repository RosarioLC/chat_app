import pytest
from store.database import Database
from store.playlist_store import PlaylistStore


class TestPlaylistStore:
    @pytest.fixture
    def db(self):
        return Database(":memory:")

    def test_create(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS playlists (id INTEGER PRIMARY KEY, name TEXT)")
        store = PlaylistStore(db)
        p = store.create("Test")
        assert p.name == "Test"
