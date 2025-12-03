#include "crypto.hpp"
#include "../include/bcrypt/bcrypt.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdexcept>

CryptoKeys derive_aes_keys(const std::vector<uint8_t>& shared_secret) {
  CryptoKeys keys{};

  EVP_PKEY_CTX* hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!hkdf) {
    throw std::runtime_error("Failed to create HKDF context");
  }

  if (EVP_PKEY_derive_init(hkdf) <= 0) {
    EVP_PKEY_CTX_free(hkdf);
    throw std::runtime_error("Failed to init HKDF");
  }

  if (EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(hkdf);
    throw std::runtime_error("Failed to set HKDF MD");
  }

  const char* salt_str = "chat_app_v0";
  if (EVP_PKEY_CTX_set1_hkdf_salt(hkdf, reinterpret_cast<const unsigned char*>(salt_str), std::strlen(salt_str)) <= 0) {
    EVP_PKEY_CTX_free(hkdf);
    throw std::runtime_error("Failed to set HKDF salt");
  }

  const char* info_str = "aes-256-gcm";
  if (EVP_PKEY_CTX_add1_hkdf_info(hkdf, reinterpret_cast<const unsigned char*>(info_str), std::strlen(info_str)) <= 0) {
    EVP_PKEY_CTX_free(hkdf);
    throw std::runtime_error("Failed to set HKDF info");
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(hkdf, shared_secret.data(), shared_secret.size()) <= 0) {
    EVP_PKEY_CTX_free(hkdf);
    throw std::runtime_error("Failed to set HKDF key");
  }

  size_t out_len = 48;
  std::vector<uint8_t> keymat(48);
  EVP_PKEY_derive(hkdf, keymat.data(), &out_len);
  EVP_PKEY_CTX_free(hkdf);

  std::memcpy(keys.aes, keymat.data(), 32);
  std::memcpy(keys.nonce, keymat.data() + 32, 12);
  return keys;
}

std::vector<uint8_t> aes_gcm_encrypt(const std::string& plaintext, const uint8_t key[32]) {
  // Generate random nonce for this message
  uint8_t random_nonce[12];
  RAND_bytes(random_nonce, 12);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, random_nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to init AES-256-GCM");
  }

  // Result format: [12 bytes nonce][ciphertext][16 bytes tag]
  std::vector<uint8_t> result(12 + plaintext.size() + 16);
  std::memcpy(result.data(), random_nonce, 12);

  int len;
  if (EVP_EncryptUpdate(ctx, result.data() + 12, &len, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Encryption failed");
  }
  int final_len;
  if (EVP_EncryptFinal_ex(ctx, result.data() + 12 + len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Final encryption step failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.data() + 12 + len + final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to get GCM tag");
  }

  EVP_CIPHER_CTX_free(ctx);
  result.resize(12 + len + final_len + 16);
  return result;
}

std::string aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext, const uint8_t key[32]) {
  // Expected format: [12 bytes nonce][ciphertext][16 bytes tag]
  if (ciphertext.size() < 28) { // 12 + 0 + 16 minimum
    throw std::runtime_error("Ciphertext too short");
  }

  // Extract nonce from the first 12 bytes
  const uint8_t* msg_nonce = ciphertext.data();
  const uint8_t* encrypted_data = ciphertext.data() + 12;
  size_t encrypted_len = ciphertext.size() - 12 - 16;
  const uint8_t* tag = ciphertext.data() + ciphertext.size() - 16;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, msg_nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to init AES-256-GCM");
  }

  std::vector<uint8_t> plaintext(encrypted_len);
  int len;
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data, encrypted_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Decryption failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to set GCM tag");
  }

  int final_len;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Final decryption step failed (authentication error)");
  }

  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(len + final_len);
  return std::string(plaintext.begin(), plaintext.end());
}

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

void generate_ephemeral_keypair(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("keygen_init");
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
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

std::vector<uint8_t> ecdh_shared_secret(const std::vector<uint8_t>& my_private, const std::vector<uint8_t>& his_public) {
  EVP_PKEY* my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_private.data(), my_private.size());
  if (!my_key) {
    throw std::runtime_error("1 Failed to create my EVP_PKEY");
  }

  EVP_PKEY* his_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, his_public.data(), his_public.size());
  if (!his_key) {
    EVP_PKEY_free(my_key);
    throw std::runtime_error("2 Failed to create his EVP_PKEY");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key, nullptr);
  if (!ctx) {
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(his_key);
    throw std::runtime_error("Failed to create EVP_PKEY_CTX for derivation");
  }

  if (EVP_PKEY_derive_init(ctx) <= 0) {
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(his_key);
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to init derivation");
  }

  if (EVP_PKEY_derive_set_peer(ctx, his_key) <= 0) {
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(his_key);
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set peer key for derivation");
  }

  size_t secret_len = 32;
  if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(his_key);
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to determine secret length");
  }

  std::vector<uint8_t> secret(secret_len);
  if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(his_key);
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to derive shared secret");
  }

  EVP_PKEY_free(my_key);
  EVP_PKEY_free(his_key);
  EVP_PKEY_CTX_free(ctx);

  return secret;
}
