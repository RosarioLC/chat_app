#include "../include/database.hpp"
#include "../include/bcrypt.hpp"
#include <iostream>

Database::Database(const std::string& db_path) : db(nullptr) {
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

std::string Database::fetch_user_username(int id) {
  auto stmt = prepare("SELECT username FROM Users WHERE id = ?");
  if (!stmt) {
    return "";
  }

  sqlite3_bind_int(stmt, 1, id);

  std::string result;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    auto text = sqlite3_column_text(stmt, 0);
    if (text) {
      result = reinterpret_cast<const char*>(text);
    }
  }

  sqlite3_finalize(stmt);
  return result;
}

void Database::add_user(const std::string& username, const std::string& password_hash) {
  auto stmt = prepare("INSERT INTO Users(username, password_hash) VALUES (?, ?)");
  if (!stmt) {
    return;
  }
  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
  }
  sqlite3_finalize(stmt);
}

int Database::check_user(const std::string& username, const std::string& password_hash) {
  sqlite3_stmt* stmt = prepare("SELECT id, password_hash FROM Users WHERE username = ?");
  if (!stmt) {
    return 0;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  int user_id = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    user_id = sqlite3_column_int(stmt, 0);
    const char* stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    if (!bcrypt_check(password_hash, stored_hash)) {
      user_id = 0;
    }
  }
  sqlite3_finalize(stmt);
  return user_id;
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
                    "password_hash TEXT);";

  char* err_msg = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
    std::cerr << "Error creating table: " << err_msg << std::endl;
    sqlite3_free(err_msg);
  }
}
