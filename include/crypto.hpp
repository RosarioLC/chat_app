#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct CryptoKeys {
  uint8_t aes[32];
  uint8_t nonce[12];
  bool ready = false;
};

CryptoKeys derive_aes_keys(const std::vector<uint8_t>& shared_secret);

std::vector<uint8_t> aes_gcm_encrypt(const std::string& plaintext, const uint8_t key[32], const uint8_t nonce[12]);

std::string aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext, const uint8_t key[32], const uint8_t nonce[12]);

/* return 60-char hash like $2b$10$N9qo8uLOickgx2ZMRZoMye... */
std::string bcrypt_hash(const std::string& password, int rounds = 10);

/* true if password matches the previously generated hash */
bool bcrypt_check(const std::string& password, const std::string& hash);

void generate_ephemeral_keypair(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey);

std::vector<uint8_t> ecdh_shared_secret(const std::vector<uint8_t>& my_private, const std::vector<uint8_t>& his_public);
