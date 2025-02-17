#pragma once

#include <map>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include <vector>
#include <assert.h>
#include <mutex>

using namespace std;

#define TNOWMS                                                \
    (std::chrono::duration_cast<std::chrono::milliseconds>(   \
         std::chrono::system_clock::now().time_since_epoch()) \
         .count())

template <class T>
class TC_TimeoutQueueSimple {
    virtual int64_t getNow() {
        return TNOWMS;
    }
public:
    virtual ~TC_TimeoutQueueSimple() = default;
    //不会生成为0的id
    uint32_t generateId() {
        unique_lock<shared_timed_mutex> lock(mtx_);
        while(++uniqId_ == 0);
        return uniqId_;
    }
    T get(uint32_t uniqId) {
        shared_lock<shared_timed_mutex> lock(mtx_);
        auto iter = id2Data_.find(uniqId);
        if (iter == id2Data_.end()) {
            return nullptr;
        }
        return iter->second.ptr;
    }
    T erase(uint32_t uniqId) {
        unique_lock<shared_timed_mutex> lock(mtx_);
        auto iter = id2Data_.find(uniqId);
        if (iter == id2Data_.end()) {
            return nullptr;
        }
        auto &data = iter->second;
        auto ptr = data.ptr;
        timeoutIds_.erase(data.iter);
        id2Data_.erase(iter);
        return ptr;
    }
    bool push(T& ptr, uint32_t uniqId, int timeoutMs) {
        assert(timeoutMs > 0);
        unique_lock<shared_timed_mutex> lock(mtx_);
        if (id2Data_.count(uniqId)) {
            return false;
        }
        Data data;
        data.iter = timeoutIds_.insert({getNow() + timeoutMs, uniqId});
        data.ptr = ptr;
        id2Data_[uniqId] = data;
        return true;
    }
    void timeout(const std::function<void(T &)> &timeoutCallback) {
        vector<T> ptrs;
        {
            auto now = getNow();
            unique_lock<shared_timed_mutex> lock(mtx_);
            for (auto iter = timeoutIds_.begin();
                 iter != timeoutIds_.upper_bound(now);) {
                auto &uniqId = iter->second;
                auto &data = id2Data_[uniqId];
                ptrs.push_back(data.ptr);
                id2Data_.erase(uniqId);
                iter = timeoutIds_.erase(iter);
            }
        }
        for (auto &ptr : ptrs) {
            timeoutCallback(ptr);
        }
    }
    size_t size() const {
        shared_lock<shared_timed_mutex> lock(mtx_);
        return id2Data_.size();
    }
    int64_t getFirstDeadline() const {
        shared_lock<shared_timed_mutex> lock(mtx_);
        if (timeoutIds_.empty()) {
            return -1;
        }
        return timeoutIds_.begin()->first;
    }

private:
    struct Data {
        T ptr;
        multimap<int64_t, uint32_t>::iterator iter;
    };
    map<uint32_t, Data> id2Data_;
    multimap<int64_t, uint32_t> timeoutIds_;
    mutable shared_timed_mutex mtx_;
    uint32_t uniqId_ = 0;
};