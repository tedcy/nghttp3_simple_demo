#include "tc_http/tc_http.h"
#include "tc_eventloop_timer.h"
#include "tc_epoller.h"
#include "tc_timeout_queue_simple.h"

struct Http3Conn {
    ~Http3Conn() {
    }
    using Ptr = std::shared_ptr<Http3Conn>;
    uint64_t getId() const {
    }
    void check_pushed_requests() {
    }
    void push_request() {
    }
    void process(int events) {
    }
    void push_request(shared_ptr<taf::TC_HttpRequest> &req) {
    }
    void setRemoveConnFunc(const function<void(uint64_t)> &func) {
    }
    void setCancelTimerFunc(const function<void(const EventLoopTimer *)> &func) {
    }
    void setEventFunc(const function<void(int, int, uint32_t)> &func) {
    }
    void initEvent() {
    }
    void setTimerFunc(const function<void(const EventLoopTimer *, double)> &func) {
    }
    void *connPtr_;
};

class TC_HttpConnKey {
    tuple<const string &, const uint32_t &> getTuple() const {
        return tie(targetAddr, targetPort);
    }
public:
    TC_HttpConnKey(const string &targetAddr, uint32_t targetPort)
        : targetAddr(targetAddr), targetPort(targetPort) {}
    string targetAddr;  //域名或ip
    uint32_t targetPort = 0;
    bool operator<(const TC_HttpConnKey &k) const {
        return getTuple() < k.getTuple();
    }
    friend ostream &operator<<(ostream &os, const TC_HttpConnKey &key) {
        os << "target=" << key.targetAddr << ":" << key.targetPort;
        return os;
    }
    string toString() const {
        ostringstream os;
        os << *this;
        return os.str();
    }
};

inline shared_ptr<Http3Conn> createHttp3Conn(const TC_HttpConnKey &key) {
    shared_ptr<Http3Conn> conn;
    return conn;
}

class TC_HttpConnPool {
public:
    using onCreateConnFunc =
        std::function<Http3Conn::Ptr(const TC_HttpConnKey &)>;
    using onGotIdleConnFunc = std::function<void(const Http3Conn *)>;
    shared_ptr<Http3Conn> id2Ptr(uint64_t id) {
        auto it = _id2Ptr.find(id);
        if (it == _id2Ptr.end()) return nullptr;
        return it->second;
    }
    void asyncGetConn(const string &targetAddr, uint32_t targetPort,
                      shared_ptr<taf::TC_HttpRequest> reqPtr,
                      const onCreateConnFunc &onCreateConn,
                      const onGotIdleConnFunc &onGotIdleConn) {
        TC_HttpConnKey key{targetAddr, targetPort};
        unique_lock<mutex> lock(asyncFuncMtx_);
        asyncFuncs_.push_back(
            [this, key = move(key),
             weakReqPtr = weak_ptr<taf::TC_HttpRequest>(reqPtr), onCreateConn,
             onGotIdleConn]() {
                getConn(key, weakReqPtr, onCreateConn, onGotIdleConn);
            });
    }
    void idleFunc() {
        vector<function<void()>> asyncFuncs;
        {
            unique_lock<mutex> lock(asyncFuncMtx_);
            asyncFuncs.swap(asyncFuncs_);
        }
        for (auto &func : asyncFuncs) {
            func();
        }
        //check_pushed_requests中可能触发删除导致迭代器失效
        //暂存垃圾桶，延迟删除
        for (auto &it : _id2Ptr) {
            auto &conn = it.second;
            if (_trash.count(conn)) continue;
            conn->check_pushed_requests();
        }
        for (auto &conn : _trash) {
            _id2Ptr.erase(conn->getId());
            cout << "remove trash|id=" << conn->getId() << endl;
        }
        _trash.clear();
    }
private:
    void getConn(const TC_HttpConnKey &key, weak_ptr<taf::TC_HttpRequest> weakReqPtr,
                 const onCreateConnFunc &onCreateConn,
                 const onGotIdleConnFunc &onGotIdleConn) {
        auto reqPtr = weakReqPtr.lock();
        if (!reqPtr) {
            cout << key << "|get idle failed|reqPtr expired" << endl;
            return;
        }
        auto it = _conns.find(key);
        if (it != _conns.end()) {
            auto conn = id2Ptr(it->second);
            onGotIdleConn(conn.get());
            cout << key << "|get idle conn" << endl;
            conn->push_request(reqPtr);
            return;
        }
        auto conn = onCreateConn(key);
        if (!conn) return;
        _conns[key] = conn->getId();
        _id2Ptr[conn->getId()] = conn;
        cout << key << "|create new conn" << endl;
        conn->push_request(reqPtr);
        conn->setRemoveConnFunc([this, key](uint64_t id) {
            _conns.erase(key);
            auto iter = _id2Ptr.find(id);
            if (iter != _id2Ptr.end()) {
                _trash.insert(iter->second);
            }
            cout << key << "|push trash|id=" << id << endl;
        });
    }
    mutex asyncFuncMtx_;
    vector<function<void()>> asyncFuncs_;
    map<TC_HttpConnKey, uint64_t> _conns;
    unordered_map<uint64_t, shared_ptr<Http3Conn>> _id2Ptr;
    set<shared_ptr<Http3Conn>> _trash;
};

class EventLoop {
public:
    EventLoop() {
        _epoller.create(1024);
    }
    void setTimer(shared_ptr<EventLoopTimer> timer, int timeoutMs) {
        _data.push(timer, timer->getId(), timeoutMs);
    }
    void cancelTimer(const EventLoopTimer* timer) {
        _data.erase(timer->getId());
    }
    void doRequest(shared_ptr<taf::TC_HttpRequest> reqPtr) {
        string targetAddr;
        uint32_t targetPort = 0;
        reqPtr->getHostPort(targetAddr, targetPort);
        _connPool.asyncGetConn(targetAddr, targetPort, reqPtr,
                               getCreateConnFunc(),
                               [this](const Http3Conn *conn) {});
    }
    void setEvent(int fd, int id, uint32_t event) {
        //TODO
        _epoller.add(fd, id, event);
        _epoller.mod(fd, id, event);
    }
    void run() {
        while (!_terminate) {
            try {
                _data.timeout([](auto &ptr) { ptr->onTimeout(); });
                int waitTime = 10;
                int64_t now = TNOWMS;
                // 例如当前时间0，即将超时事件时间3，最大超时时间10
                // 那么wait 3即可
                if (_data.getFirstDeadline() != -1 &&
                    _data.getFirstDeadline() < now + waitTime) {
                    waitTime = _data.getFirstDeadline() - now;
                    waitTime = max(waitTime, 0);
                }

                int num = _epoller.wait(waitTime);

                for (int i = 0; i < num; ++i) {
                    epoll_event ev = _epoller.get(i);

                    uint64_t connId = ev.data.u64;

                    auto conn = _connPool.id2Ptr(connId);

                    if (!conn) continue;

                    conn->process(ev.events);
                }

                _connPool.idleFunc();
            } catch (exception &ex) {
                std::cerr << "[TC_HttpAsync::run] error:" << ex.what() << endl;
            }
        }
    }
private:
    TC_HttpConnPool::onCreateConnFunc getCreateConnFunc() {
        return [this](const TC_HttpConnKey &key) {
            shared_ptr<Http3Conn> c;
            return c;
        };
    }
    TC_Epoller _epoller;
    bool _terminate = false;
    TC_TimeoutQueueSimple<shared_ptr<EventLoopTimer>> _data;
    TC_HttpConnPool _connPool;
};