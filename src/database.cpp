#include "../include/database.hpp"
#include "../include/crypto.hpp"
#include <iostream>

Database::Database(const std::string& db_path) : db(nullptr), db_path(db_path) {
  if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
    std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
    db = nullptr;
  } else {
    init_tables();
  }
}

Database::~Database() {
  if (db) {
    sqlite3_close(db);
    db = nullptr;
  }
}

sqlite3_stmt* Database::prepare(const char* sql) {
  sqlite3_stmt* stmt = nullptr;
  if (!db) {
    return nullptr;
  }

  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
    return nullptr;
  }
  return stmt;
}

static inline bool exec_sql(sqlite3* db, const char* sql) {
  char* err = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    if (err) {
      std::cerr << err << std::endl;
      sqlite3_free(err);
    }
    return false;
  }
  return true;
}

int Database::fetch_user_id(const std::string& username) {
  auto stmt = prepare("SELECT id FROM Users WHERE username = ?");
  if (!stmt) {
    return -1;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    id = sqlite3_column_int(stmt, 0);
  }

  sqlite3_finalize(stmt);
  return id;
}

std::vector<uint8_t> Database::fetch_public_key(int user_id) {
  sqlite3_stmt* stmt = prepare("SELECT pubkey FROM Users WHERE id = ?");
  if (!stmt) {
    return {};
  }
  sqlite3_bind_int(stmt, 1, user_id);

  std::vector<uint8_t> key;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const void* blob = sqlite3_column_blob(stmt, 0);
    int size = sqlite3_column_bytes(stmt, 0);
    key.assign(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
  }
  sqlite3_finalize(stmt);
  return key;
}

void Database::add_user(const std::string& username, const std::string& password_hash, const std::vector<uint8_t>& pubkey) {
  auto stmt = prepare("INSERT INTO Users(username, password_hash, pubkey, privkey) VALUES (?, ?, ?, ?)");
  if (!stmt) {
    return;
  }
  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

  std::vector<uint8_t> client_pubkey, privkey;
  if (pubkey.empty()) {
    // Fallback: server generates (NOT true E2EE)
    generate_ephemeral_keypair(client_pubkey, privkey);
  } else {
    // Use client-provided public key (true E2EE - client keeps private key)
    client_pubkey = pubkey;
    // privkey remains empty - server never sees it
  }

  sqlite3_bind_blob(stmt, 3, client_pubkey.data(), client_pubkey.size(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, privkey.data(), privkey.size(), SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
  }
  sqlite3_finalize(stmt);
}

int Database::check_user(const std::string& username, const std::string& password) {
  sqlite3_stmt* stmt = prepare("SELECT id, password_hash FROM Users WHERE username = ?");
  if (!stmt) {
    return 0;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  int user_id = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    user_id = sqlite3_column_int(stmt, 0);
    const char* stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    if (!bcrypt_check(password, stored_hash)) {
      user_id = 0;
    }
  }
  sqlite3_finalize(stmt);
  return user_id;
}

void Database::update_public_key(int user_id, const std::vector<uint8_t>& pubkey) {
  auto stmt = prepare("UPDATE Users SET pubkey = ? WHERE id = ?");
  if (!stmt) {
    return;
  }

  sqlite3_bind_blob(stmt, 1, pubkey.data(), pubkey.size(), SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, user_id);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    std::cerr << "Update public key failed: " << sqlite3_errmsg(db) << std::endl;
  }
  sqlite3_finalize(stmt);
}

void Database::remove_user(int id) {
  auto stmt = prepare("DELETE FROM Users WHERE id = ?");
  if (!stmt) {
    return;
  }

  sqlite3_bind_int(stmt, 1, id);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    std::cerr << "Delete failed: " << sqlite3_errmsg(db) << std::endl;
  }

  sqlite3_finalize(stmt);
}

void Database::remove_user(const std::string& username) {
  auto stmt = prepare("DELETE FROM Users WHERE username = ?");
  if (!stmt) {
    return;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    std::cerr << "Delete failed: " << sqlite3_errmsg(db) << std::endl;
  }

  sqlite3_finalize(stmt);
}

void Database::init_tables() {
  if (!db) {
    return;
  }
  const char* sql = "CREATE TABLE IF NOT EXISTS Users("
                    "id INTEGER PRIMARY KEY,"
                    "username TEXT UNIQUE,"
                    "pubkey BLOB,"
                    "privkey BLOB,"
                    "password_hash TEXT);";
  exec_sql(db, sql);
}

bool Database::delete_database() {
  if (!db) {
    std::cerr << "Database not open; cannot wipe." << std::endl;
    return false;
  }
  exec_sql(db, "BEGIN TRANSACTION;");
  if (!exec_sql(db, "DELETE FROM Users;")) {
    exec_sql(db, "ROLLBACK;");
    return false;
  }
  exec_sql(db, "COMMIT;");
  exec_sql(db, "VACUUM;");
  return true;
}
