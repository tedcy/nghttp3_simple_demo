#pragma once

#include <atomic>

class EventLoopTimer {
public:
  virtual void onTimeout() = 0;
  uint64_t getId() const {
    return id_;
  }
private:
  static uint64_t generateId() {
    static std::atomic<uint64_t> id = {0};
    return ++id;
  }
  uint64_t id_ = generateId();
};