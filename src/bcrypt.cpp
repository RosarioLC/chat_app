#include "../include/bcrypt.hpp"
#include "../include/bcrypt/bcrypt.h"

std::string bcrypt_hash(const std::string& password, int rounds) {
  char salt[32] = {0};
  char hash[128] = {0};

  bcrypt_gensalt(rounds, salt);
  bcrypt_hashpw(password.c_str(), salt, hash);
  return std::string(hash);
}

bool bcrypt_check(const std::string& password, const std::string& hash) {
  return bcrypt_checkpw(password.c_str(), hash.c_str()) == 0;
}
