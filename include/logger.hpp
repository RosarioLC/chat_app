#pragma once
#include <string>

// Logger: minimal, centralized logging utility.
// Usage: `Logger::log(Logger::INFO, "message");`
// Honors `LOG_LEVEL` env var: DEBUG, INFO, WARN, ERROR.
class Logger {
public:
  enum Level { DEBUG, INFO, WARN, ERROR };
  static void log(Level level, const std::string& msg);
  // Helper to prefix messages with fd/user context.
  static std::string with_conn(int fd, int user_id, const std::string& msg);
};
