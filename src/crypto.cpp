#include "../include/crypto.hpp"
#include "../include/bcrypt/bcrypt.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

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

void generate_ephemeral_keypair(std::vector<uint8_t> pubkey, std::vector<uint8_t> privkey) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (!EVP_PKEY_keygen_init(ctx) <= 0) {
    std::runtime_error("keygen_init");
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    throw std::runtime_error("keygen");
  }

  EVP_PKEY_CTX_free(ctx);

  size_t pub_len = 32;
  size_t priv_len = 32;

  pubkey.resize(pub_len);
  privkey.resize(priv_len);

  EVP_PKEY_get_raw_public_key(pkey, pubkey.data(), &pub_len);
  EVP_PKEY_get_raw_private_key(pkey, privkey.data(), &priv_len);
  EVP_PKEY_free(pkey);
}
