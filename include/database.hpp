#pragma once
#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>

class Database {
private:
  sqlite3* db;
  sqlite3_stmt* prepare(const char* sql);
  void init_tables();

public:
  Database(const std::string& db_path);
  ~Database();

  int fetch_user_id(const std::string& username);
  std::string fetch_user_username(int id);

  void add_user(const std::string& username, const std::string& password_hash);

  int check_user(const std::string& udername, const std::string& password);

  void remove_user(int id);
  void remove_user(const std::string& username);
};

#endif // DATABASE_H
