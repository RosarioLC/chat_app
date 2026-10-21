import pytest
from store.database import Database
from store.liked_song_store import LikedSongStore
from model.track import Track


class TestLikedSongStore:
    @pytest.fixture
    def db(self):
        return Database(":memory:")

    def test_add(self, db):
        t = Track(id=1, title="Test")
        store = LikedSongStore(db)
        store.add(t)
        db.commit()
