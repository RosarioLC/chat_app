#pragma once
#ifndef DATABASE_H
#define DATABASE_H

// Database API: wraps SQLite for user storage
//
// Responsibilities:
// - Open/create a SQLite database file at the provided path
// - Ensure the application schema exists (Users table)
// - Provide CRUD-style operations for user records
// - Offer a safe data wipe that preserves the DB file and schema
//
// Notes:
// - Passwords are stored as bcrypt hashes (see bcrypt.hpp)
// - Each user has an X25519 keypair (pub/priv) stored as BLOBs
// - All methods assume `init_tables()` has been called by the constructor
#include <cstdint>
#include <sqlite3.h>
#include <string>
#include <vector>

// Manages a SQLite database file and user records
class Database {
private:
  sqlite3* db;
  std::string db_path;
  sqlite3_stmt* prepare(const char* sql);
  void init_tables();

public:
  // Open or create the database at `db_path` and ensure schema exists.
  // If the file does not exist, SQLite will create it. The constructor
  // calls `init_tables()` which creates the `Users` table if missing.
  Database(const std::string& db_path);
  // Close the database connection. Safe to call even if already closed.
  ~Database();

  // Lookup helpers
  // Returns the numeric id for a `username`, or -1 if not found.
  int fetch_user_id(const std::string& username);
  // Returns the username for a numeric `id`, or empty string if not found.
  std::string fetch_user_username(int id);
  // Returns the raw public key BLOB for a user id; empty vector if not found.
  std::vector<uint8_t> fetch_public_key(int user_id);

  // Create a user record.
  // Inputs:
  // - `username`: unique textual identifier
  // - `password_hash`: bcrypt hash (use `bcrypt_hash()` to generate)
  // Behavior:
  // - Generates an X25519 keypair and stores the pub/priv as BLOBs
  // - Inserts into `Users(username, password_hash, pubkey, privkey)`
  void add_user(const std::string& username, const std::string& password_hash);

  // Verify credentials.
  // Inputs: raw `username` and `password` (plaintext).
  // Returns: user id on success, or 0 on failure.
  // Implementation compares the provided password against the stored bcrypt hash.
  int check_user(const std::string& username, const std::string& password);

  // Remove user by id or username. No-op if the record doesn't exist.
  void remove_user(int id);
  void remove_user(const std::string& username);

  // Wipe all data from tables; keeps file and schema.
  // Returns: true on success, false if any SQL error occurs.
  // Implementation deletes rows in known tables and may run VACUUM.
  bool delete_database();
};

#endif // DATABASE_H
