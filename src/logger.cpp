#include "logger.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

static const char* level_name(Logger::Level lvl) {
  switch (lvl) {
    case Logger::DEBUG:
      return "DEBUG";
    case Logger::INFO:
      return "INFO";
    case Logger::WARN:
      return "WARN";
    case Logger::ERROR:
      return "ERROR";
  }
  return "INFO";
}

static Logger::Level runtime_level() {
  const char* env = std::getenv("LOG_LEVEL");
  if (!env)
    return Logger::INFO;
  std::string v(env);
  if (v == "DEBUG")
    return Logger::DEBUG;
  if (v == "INFO")
    return Logger::INFO;
  if (v == "WARN")
    return Logger::WARN;
  if (v == "ERROR")
    return Logger::ERROR;
  return Logger::INFO;
}

void Logger::log(Level level, const std::string& msg) {
  static Level min_level = runtime_level();
  if (level < min_level)
    return;
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm = *std::localtime(&t);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%F %T") << " [" << level_name(level) << "] " << msg;
  std::cout << oss.str() << std::endl;
}

std::string Logger::with_conn(int fd, int user_id, const std::string& msg) {
  std::ostringstream oss;
  oss << "(fd=" << fd << ", uid=" << user_id << ") " << msg;
  return oss.str();
}
