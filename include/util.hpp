#pragma once
#include <string>

static inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

int check(int result, const char* funcname) {
  if (result < 0) {
    perror(funcname);
    return -1;
  }
  return 0;
}
