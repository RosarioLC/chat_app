#pragma once
#include <cstdint>
#include <string>
#include <vector>

/* return 60-char hash like $2b$10$N9qo8uLOickgx2ZMRZoMye... */
std::string bcrypt_hash(const std::string& password, int rounds = 10);

/* true if password matches the previously generated hash */
bool bcrypt_check(const std::string& password, const std::string& hash);

void generate_ephemeral_keypair(std::vector<uint8_t> pubkey, std::vector<uint8_t> privkey);
