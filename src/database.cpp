#include "../include/database.hpp"
#include "../include/bcrypt.hpp"
#include <iostream>
#include <openssl/evp.h>

static void generate_keypair(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);

  size_t pub_len = 32;
  size_t priv_len = 32;

  pub.resize(pub_len);
  priv.resize(priv_len);

  EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);
  EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);
  EVP_PKEY_free(pkey);
}

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

void Database::add_user(const std::string& username, const std::string& password_hash) {
  auto stmt = prepare("INSERT INTO Users(username, password_hash, pubkey, privkey) VALUES (?, ?, ?, ?)");
  if (!stmt) {
    return;
  }
  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

  std::vector<uint8_t> pub, priv;
  generate_keypair(pub, priv);

  sqlite3_bind_blob(stmt, 3, pub.data(), pub.size(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, priv.data(), priv.size(), SQLITE_STATIC);

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
  //   delete_database();
  const char* sql = "CREATE TABLE IF NOT EXISTS Users("
                    "id INTEGER PRIMARY KEY,"
                    "username TEXT UNIQUE,"
                    "pubkey BLOB,"
                    "privkey BLOB,"
                    "password_hash TEXT);";

  char* err_msg = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
    std::cerr << "Error creating table: " << err_msg << std::endl;
    sqlite3_free(err_msg);
  }
}

bool Database::delete_database() {
  if (!db) {
    std::cerr << "Database not open; cannot wipe." << std::endl;
    return false;
  }

  char* err_msg = nullptr;
  const char* wipe_users = "DELETE FROM Users;";
  if (sqlite3_exec(db, wipe_users, nullptr, nullptr, &err_msg) != SQLITE_OK) {
    std::cerr << "Error wiping Users: " << err_msg << std::endl;
    sqlite3_free(err_msg);
    return false;
  }

  const char* vacuum = "VACUUM;";
  if (sqlite3_exec(db, vacuum, nullptr, nullptr, &err_msg) != SQLITE_OK) {
    std::cerr << "VACUUM failed: " << err_msg << std::endl;
    sqlite3_free(err_msg);
  }

  return true;
}
