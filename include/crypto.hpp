#pragma once
// Crypto module: ECDH (X25519), HKDF derivation of AES-256-GCM keys,
// per-message random nonce encryption/decryption, bcrypt helpers.
#include <cstdint>
#include <string>
#include <vector>

// AES-256-GCM key material derived via HKDF from ECDH shared secret.
// Note: Nonce must be unique per message. Our encrypt function prepends
// a 12-byte random nonce to the ciphertext.
struct CryptoKeys {
  uint8_t aes[32];
  uint8_t nonce[12];
  bool ready = false;
};

CryptoKeys derive_aes_keys(const std::vector<uint8_t>& shared_secret);

// Encrypts plaintext as: [12-byte random nonce][ciphertext][16-byte GCM tag]
std::vector<uint8_t> aes_gcm_encrypt(const std::string& plaintext, const uint8_t key[32]);

// Decrypts payload expecting the format above; extracts nonce from the first 12 bytes.
std::string aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext, const uint8_t key[32]);

/* return 60-char hash like $2b$10$N9qo8uLOickgx2ZMRZoMye... */
std::string bcrypt_hash(const std::string& password, int rounds = 10);

/* true if password matches the previously generated hash */
bool bcrypt_check(const std::string& password, const std::string& hash);

void generate_ephemeral_keypair(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey);

std::vector<uint8_t> ecdh_shared_secret(const std::vector<uint8_t>& my_private, const std::vector<uint8_t>& his_public);
