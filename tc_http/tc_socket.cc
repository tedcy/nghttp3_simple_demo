#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cassert>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tc_socket.h"
#include "tc_common.h"

namespace taf
{

set<int> TC_Socket::_s_reusePorts;

void TC_Socket::addReusePort(int port)
{
    _s_reusePorts.insert(port);
}

TC_Socket::TC_Socket() : _sock(INVALID_SOCKET), _bOwner(true), _iDomain(AF_INET)
{
}

TC_Socket::~TC_Socket()
{
    if(_bOwner)
    {
        close();
    }
}

void TC_Socket::init(int fd, bool bOwner, int iDomain)
{
    if(_bOwner)
    {
        close();
    }

    _sock       = fd;
    _bOwner     = bOwner;
    _iDomain    = iDomain;
}

void TC_Socket::createSocket(int iSocketType, int iDomain)
{
    assert(iSocketType == SOCK_STREAM || iSocketType == SOCK_DGRAM);
    assert(iDomain == AF_INET || iDomain == AF_INET6);
    close();

    _iDomain    = iDomain;
    _sock       = socket(iDomain, iSocketType, 0);

    if(_sock < 0)
    {
        _sock = INVALID_SOCKET;
        throw TC_Socket_Exception("[TC_Socket::createSocket] create socket error! :" + string(strerror(errno)));
    }
}

void TC_Socket::getPeerName(string &sPeerAddress, uint16_t &iPeerPort)
{
    assert(_iDomain == AF_INET || _iDomain == AF_INET6);

    struct sockaddr_storage stPeer;
    bzero(&stPeer, sizeof(stPeer));
    socklen_t iPeerLen = sizeof(stPeer);

    getPeerName((struct sockaddr *)&stPeer, iPeerLen);

    char sAddr[INET6_ADDRSTRLEN] = {};

    struct sockaddr_in *p4 = (struct sockaddr_in *)&stPeer;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&stPeer;
    if (_iDomain == AF_INET) {
        inet_ntop(_iDomain, &p4->sin_addr, sAddr, sizeof(sAddr));
    } else {
        inet_ntop(_iDomain, &p6->sin6_addr, sAddr, sizeof(sAddr));
    }

    sPeerAddress= sAddr;
    iPeerPort   = ntohs(p4->sin_port);
}

void TC_Socket::getPeerName(string &sPathName)
{
    assert(_iDomain == AF_LOCAL);

    struct sockaddr_un stSock;
    bzero(&stSock, sizeof(struct sockaddr_un));
    socklen_t iSockLen = sizeof(stSock);
    getPeerName((struct sockaddr *)&stSock, iSockLen);

    sPathName = stSock.sun_path;
}

void TC_Socket::getPeerName(struct sockaddr *pstPeerAddr, socklen_t &iPeerLen)
{
    if(getpeername(_sock, pstPeerAddr, &iPeerLen) < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::getPeerName] getpeername error", errno);
    }
}

void TC_Socket::getSockName(string &sSockAddress, uint16_t &iSockPort)
{
    assert(_iDomain == AF_INET || _iDomain == AF_INET6);

    struct sockaddr_storage stAddr;
    bzero(&stAddr, sizeof(stAddr));
    socklen_t iSockLen = sizeof(stAddr);

    getSockName((struct sockaddr*)&stAddr, iSockLen);

    char sAddr[INET6_ADDRSTRLEN] = {};

    struct sockaddr_in *p4 = (struct sockaddr_in *)&stAddr;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&stAddr;
    if (_iDomain == AF_INET) {
        inet_ntop(_iDomain, &p4->sin_addr, sAddr, sizeof(sAddr));
    } else {
        inet_ntop(_iDomain, &p6->sin6_addr, sAddr, sizeof(sAddr));
    }

    sSockAddress = sAddr;
    iSockPort = ntohs(p4->sin_port);
}

void TC_Socket::getSockName(string &sPathName)
{
    assert(_iDomain == AF_LOCAL);

    struct sockaddr_un stSock;
    bzero(&stSock, sizeof(struct sockaddr_un));
    socklen_t iSockLen = sizeof(stSock);
    getSockName((struct sockaddr *)&stSock, iSockLen);

    sPathName = stSock.sun_path;
}

void TC_Socket::getSockName(struct sockaddr *pstSockAddr, socklen_t &iSockLen)
{
    if(getsockname(_sock, pstSockAddr, &iSockLen) < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::getSockName] getsockname error", errno);
    }
}

int TC_Socket::accept(TC_Socket &tcSock, struct sockaddr *pstSockAddr, socklen_t &iSockLen)
{
    assert(tcSock._sock == INVALID_SOCKET);

    int ifd;

    while ((ifd = ::accept(_sock, pstSockAddr, &iSockLen)) < 0 && errno == EINTR);

    tcSock._sock    = ifd;
    tcSock._iDomain = _iDomain;

    return tcSock._sock;
}

static int tc_safe_gethostbyname_r(vector<char> &buf, const string &sAddr,
                                   struct hostent *stHostent,
                                   struct hostent **pstHostent) {
    static constexpr int initSize = 2048;
    int iError = 0;
    if (buf.size() < initSize) {
        buf.resize(initSize);
    }

    while ((gethostbyname_r(sAddr.c_str(), stHostent, buf.data(), buf.size(),
                            pstHostent, &iError)) == ERANGE) {
        buf.resize(buf.size() * 2);
    }
    return iError;
}

void TC_Socket::parseAddr(int domain, const string &sAddr, struct sockaddr_storage & stAddr)
{
    void* dst = domain == AF_INET ? (void*)&reinterpret_cast<struct sockaddr_in &>(stAddr).sin_addr :
        (void*)&reinterpret_cast<struct sockaddr_in6 &>(stAddr).sin6_addr;
    int iRet = inet_pton(domain, sAddr.c_str(), dst);
    if(iRet < 0) {
        throw TC_Socket_Exception("[TC_Socket::parseAddr] inet_pton error", errno);
    } else if(iRet == 0) {
        struct hostent stHostent;
        struct hostent *pstHostent;
        vector<char> buf;
        int iError = tc_safe_gethostbyname_r(buf, sAddr, &stHostent, &pstHostent);

        if (pstHostent == NULL)
        {
            throw TC_Socket_Exception(
                "[TC_Socket::parseAddr] tc_safe_gethostbyname_r(" +
                TC_Common::tostr(domain) + ", " + sAddr +
                ") error:" + string(hstrerror(iError)));
        }
        else if (pstHostent->h_addrtype != domain)
        {
            throw TC_Socket_Exception(
                "[TC_Socket::parseAddr] tc_safe_gethostbyname_r return domain "
                "error.");
        }
        else
        {
            if (domain == AF_INET) {
                struct sockaddr_in* p4 = (struct sockaddr_in*)&stAddr;
                p4->sin_addr = *(struct in_addr *) pstHostent->h_addr;
            } else {
                struct sockaddr_in6* p6 = (struct sockaddr_in6*)&stAddr;
                p6->sin6_addr = *(struct in6_addr *) pstHostent->h_addr;
            }
        }
    }
}

vector<string> TC_Socket::host2Addrs(const string &sHost, string * err)
{
    char ignoreBuffer[sizeof(struct sockaddr_in6) + sizeof(struct sockaddr_in)];
    if (inet_pton(AF_INET, sHost.c_str(), ignoreBuffer) == 1) {
        // sHost是一个ipv4地址，无需解析
        return {sHost};
    }

    if (inet_pton(AF_INET6, sHost.c_str(), ignoreBuffer) == 1) {
        // sHost是一个ipv6地址，无需解析
        return {sHost};
    }

    // dns解析
    struct hostent stHostent;
    struct hostent *pstHostent;
    vector<char> buf;
    int iError = tc_safe_gethostbyname_r(buf, sHost, &stHostent, &pstHostent);

    if (pstHostent == NULL)
    {
        // 解析失败
        if (err)
            *err = hstrerror(iError);
        return {};
    }

    vector<string> addrs;
    for (int i = 0; i < pstHostent->h_length; ++i) {
        char * addr = pstHostent->h_addr_list[i];
        if (!addr)
            break;

        // 转换成ip字符串
        char sAddr[INET6_ADDRSTRLEN] = {};
        int domain = pstHostent->h_addrtype;
        const char* retStr = nullptr;

        if (domain == AF_INET) {
            retStr = inet_ntop(domain, (struct in_addr*)addr, sAddr, sizeof(sAddr));
        } else {
            retStr = inet_ntop(domain, (struct in6_addr*)addr, sAddr, sizeof(sAddr));
        }

        if (retStr) {
            addrs.push_back(sAddr);
        } else {
            if (err) {
                char buf[128] = {};
                snprintf(buf, sizeof(buf), "{addr[%d] inet_ntop error:%d,%s}",
                        i, errno, strerror(errno));
                *err += buf;
            }
        }
    }

    return addrs;
}

void TC_Socket::parseAddr(const string &sAddr, struct in_addr &stSinAddr)
{
    int iRet = inet_pton(AF_INET, sAddr.c_str(), &stSinAddr);
    if(iRet < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::parseAddr] inet_pton error", errno);
    }
    else if(iRet == 0)
    {
        struct hostent stHostent;
        struct hostent *pstHostent;
        vector<char> buf;
        int iError = tc_safe_gethostbyname_r(buf, sAddr, &stHostent, &pstHostent);

        if (pstHostent == NULL)
        {
            throw TC_Socket_Exception(
                "[TC_Socket::parseAddr] tc_safe_gethostbyname_r error! :" +
                string(hstrerror(iError)));
        }
        else
        {
            stSinAddr = *(struct in_addr *) pstHostent->h_addr;
        }
    }
}

pair<string, uint32_t> TC_Socket::sockaddr2IpPort(
    const struct sockaddr_in *addr) {
    string ip;
    uint32_t port;

    char ip_buffer[INET_ADDRSTRLEN];
    inet_ntop(
        AF_INET, &addr->sin_addr, ip_buffer,
        sizeof(ip_buffer));  // 将IP地址从网络字节顺序转换为点分十进制字符串
    ip = ip_buffer;
    port = ntohs(addr->sin_port);  // 将端口从网络字节顺序转换为主机字节顺序

    return {ip, port};
}

struct sockaddr_in TC_Socket::ipPort2Sockaddr(const std::string &ip,
                                              uint32_t port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;    // 设置地址族
    addr.sin_port = htons(port);  // 将端口转换为网络字节顺序
    inet_pton(AF_INET, ip.c_str(),
              &addr.sin_addr);  // 将IP地址转换为网络字节顺序
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));  // 填充字节置为零
    return addr;
}

void TC_Socket::bind(const string &sServerAddr, int port)
{
    assert(_iDomain == AF_INET || _iDomain == AF_INET6);

    struct sockaddr_storage stBindAddr;
    bzero(&stBindAddr, sizeof(stBindAddr));

    struct sockaddr_in *p4 = (struct sockaddr_in *)&stBindAddr;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&stBindAddr;
    p4->sin_family   = _iDomain;
    p4->sin_port     = htons(port);

    if (sServerAddr == "")
    {
        if (_iDomain == AF_INET)
            p4->sin_addr.s_addr = htonl(INADDR_ANY);
        else
            p6->sin6_addr = IN6ADDR_ANY_INIT;
    }
    else
    {
        parseAddr(_iDomain, sServerAddr, stBindAddr);
    }

    try
    {
        bind((struct sockaddr *)&stBindAddr, sizeof(stBindAddr));
    }
    catch(...)
    {
        throw TC_Socket_Exception("[TC_Socket::bind] bind '" + sServerAddr + ":" + TC_Common::tostr(port) + "' error", errno);
    }
}

void TC_Socket::bind(const char *sPathName)
{
    assert(_iDomain == AF_LOCAL);

    unlink(sPathName);

    struct sockaddr_un stBindAddr;
    bzero(&stBindAddr, sizeof(struct sockaddr_un));
    stBindAddr.sun_family = _iDomain;
    strncpy(stBindAddr.sun_path, sPathName, sizeof(stBindAddr.sun_path));

    try
    {
        bind((struct sockaddr *)&stBindAddr, sizeof(stBindAddr));
    }
    catch(...)
    {
        throw TC_Socket_Exception("[TC_Socket::bind] bind '" + string(sPathName) + "' error", errno);
    }
}

void TC_Socket::bind(struct sockaddr *pstBindAddr, socklen_t iAddrLen)
{
    struct sockaddr_in *p4 = (struct sockaddr_in *)pstBindAddr;
    int port = ntohs(p4->sin_port);

    //如果服务器终止后,服务器可以第二次快速启动而不用等待一段时间
    int iReuseAddr = 1;
    setSockOpt(SO_REUSEADDR, (const void *)&iReuseAddr, sizeof(int), SOL_SOCKET);

    // 多进程共用端口
    if (port && _s_reusePorts.count(port)) {
        int iReusePort = 1;
        setSockOpt(SO_REUSEPORT, (const void *)&iReusePort, sizeof(int), SOL_SOCKET);
    }

    if(::bind(_sock, pstBindAddr, iAddrLen) < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::bind] bind error", errno);
    }
}

void TC_Socket::close()
{
    if (_sock != INVALID_SOCKET)
    {
        ::close(_sock);
        _sock = INVALID_SOCKET;
    }
}

int TC_Socket::connectNoThrow(const string &sServerAddr, uint16_t port)
{
    assert(_iDomain == AF_INET);

    if (sServerAddr == "")
    {
        throw TC_Socket_Exception("[TC_Socket::connect] server address is empty error!");
    }

    struct sockaddr_storage stServerAddr;
    bzero(&stServerAddr, sizeof(stServerAddr));

    struct sockaddr_in *p4 = (struct sockaddr_in *)&stServerAddr;
    p4->sin_family = _iDomain;
    p4->sin_port = htons(port);

    parseAddr(_iDomain, sServerAddr, stServerAddr);

    return connect((struct sockaddr*)&stServerAddr, sizeof(stServerAddr));
}

int TC_Socket::connectNoThrow(struct sockaddr* addr)
{
    assert(_iDomain == AF_INET);

    return connect(addr, sizeof(struct sockaddr));
}

void TC_Socket::connect(const string &sServerAddr, uint16_t port)
{
    int ret = connectNoThrow(sServerAddr, port);

    if(ret < 0)
    {
        throw TC_SocketConnect_Exception("[TC_Socket::connect] connect error", errno);
    }
}

void TC_Socket::connect(const char *sPathName)
{
    int ret = connectNoThrow(sPathName);
    if(ret < 0)
    {
        throw TC_SocketConnect_Exception("[TC_Socket::connect] connect error", errno);
    }
}

int TC_Socket::connectNoThrow(const char *sPathName)
{
    assert(_iDomain == AF_LOCAL);

    struct sockaddr_un stServerAddr;
    bzero(&stServerAddr, sizeof(struct sockaddr_un));
    stServerAddr.sun_family = _iDomain;
    strncpy(stServerAddr.sun_path, sPathName, sizeof(stServerAddr.sun_path));

    return connect((struct sockaddr *)&stServerAddr, sizeof(stServerAddr));
}

int TC_Socket::connect(struct sockaddr *pstServerAddr, socklen_t serverLen)
{
    return ::connect(_sock, pstServerAddr, serverLen);
}

void TC_Socket::listen(int iConnBackLog)
{
    if (::listen(_sock, iConnBackLog) < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::listen] listen error", errno);
    }
}

int TC_Socket::recv(void *pvBuf, size_t iLen, int iFlag)
{
    return ::recv(_sock, pvBuf, iLen, iFlag);
}

int TC_Socket::send(const void *pvBuf, size_t iLen, int iFlag)
{
    return ::send(_sock, pvBuf, iLen, iFlag);
}

int TC_Socket::recvfrom(void *pvBuf, size_t iLen, string &sFromAddr, uint16_t &iFromPort, int iFlags)
{
    struct sockaddr_storage stPeer;
    socklen_t iFromLen = sizeof(stPeer);

    bzero(&stPeer, sizeof(stPeer));

    int iBytes = recvfrom(pvBuf, iLen, (struct sockaddr*)&stPeer, iFromLen, iFlags);
    if (iBytes >= 0)
    {
        char sAddr[INET6_ADDRSTRLEN] = {};

        struct sockaddr_in *p4 = (struct sockaddr_in *)&stPeer;
        struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&stPeer;
        if (_iDomain == AF_INET) {
            inet_ntop(_iDomain, &p4->sin_addr, sAddr, sizeof(sAddr));
        } else {
            inet_ntop(_iDomain, &p6->sin6_addr, sAddr, sizeof(sAddr));
        }

        sFromAddr = sAddr;
        iFromPort = ntohs(p4->sin_port);
    }

    return iBytes;
}

int TC_Socket::recvfrom(void *pvBuf, size_t iLen, struct sockaddr *pstFromAddr, socklen_t &iFromLen, int iFlags)
{
    return ::recvfrom(_sock, pvBuf, iLen, iFlags, pstFromAddr, &iFromLen);
}

int TC_Socket::sendto(const void *pvBuf, size_t iLen, const string &sToAddr, uint16_t port, int iFlags)
{
    struct sockaddr_storage stToAddr;
    struct sockaddr_in *p4 = (struct sockaddr_in *)&stToAddr;

    bzero(&stToAddr, sizeof(stToAddr));

    p4->sin_family = _iDomain;
    p4->sin_port = htons(port);

    if (sToAddr == "" && _iDomain == AF_INET)
    {
        p4->sin_addr.s_addr = htonl(INADDR_BROADCAST);
    }
    else
    {
        parseAddr(_iDomain, sToAddr, stToAddr);
    }

    return sendto(pvBuf, iLen, (struct sockaddr*)&stToAddr, sizeof(stToAddr), iFlags);
}

int TC_Socket::sendto(const void *pvBuf, size_t iLen, struct sockaddr *pstToAddr, socklen_t iToLen, int iFlags)
{
    return ::sendto(_sock, pvBuf, iLen, iFlags, pstToAddr, iToLen);
}

void TC_Socket::shutdown(int iHow)
{
    if (::shutdown(_sock, iHow) < 0)
    {
        throw TC_Socket_Exception("[TC_Socket::shutdown] shutdown error", errno);
    }
}

void TC_Socket::setblock(bool bBlock)
{
    assert(_sock != INVALID_SOCKET);

    setblock(_sock, bBlock);
}

int TC_Socket::setSockOpt(int opt, const void *pvOptVal, socklen_t optLen, int level)
{
    return setsockopt(_sock, level, opt, pvOptVal, optLen);
}

int TC_Socket::getSockOpt(int opt, void *pvOptVal, socklen_t &optLen, int level)
{
    return getsockopt(_sock, level, opt, pvOptVal, &optLen);
}

void TC_Socket::setNoCloseWait()
{
    linger stLinger;
    stLinger.l_onoff = 1;  //在close socket调用后, 但是还有数据没发送完毕的时候容许逗留
    stLinger.l_linger = 0; //容许逗留的时间为0秒

    if(setSockOpt(SO_LINGER, (const void *)&stLinger, sizeof(linger), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setNoCloseWait] error", errno);
    }
}

void TC_Socket::setCloseWait(int delay)
{
    linger stLinger;
    stLinger.l_onoff = 1;  //在close socket调用后, 但是还有数据没发送完毕的时候容许逗留
    stLinger.l_linger = delay; //容许逗留的时间为delay秒

    if(setSockOpt(SO_LINGER, (const void *)&stLinger, sizeof(linger), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setCloseWait] error", errno);
    }
}

void TC_Socket::setCloseWaitDefault()
{
    linger stLinger;
    stLinger.l_onoff  = 0;
    stLinger.l_linger = 0;

    if(setSockOpt(SO_LINGER, (const void *)&stLinger, sizeof(linger), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setCloseWaitDefault] error", errno);
    }
}

void TC_Socket::setTcpNoDelay()
{
    int flag = 1;

    if(setSockOpt(TCP_NODELAY, (char*)&flag, int(sizeof(int)), IPPROTO_TCP) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setTcpNoDelay] error", errno);
    }
}

void TC_Socket::setKeepAlive()
{
    int flag = 1;
    if(setSockOpt(SO_KEEPALIVE, (char*)&flag, int(sizeof(int)), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setKeepAlive] error", errno);
    }
}

void TC_Socket::setSendBufferSize(int sz)
{
    if(setSockOpt(SO_SNDBUF, (char*)&sz, int(sizeof(int)), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setSendBufferSize] error", errno);
    }
}

int TC_Socket::getSendBufferSize()
{
    int sz;
    socklen_t len = sizeof(sz);
    if(getSockOpt(SO_SNDBUF, (void*)&sz, len, SOL_SOCKET) == -1 || len != sizeof(sz))
    {
        throw TC_Socket_Exception("[TC_Socket::getSendBufferSize] error", errno);
    }

    return sz;
}

void TC_Socket::setRecvBufferSize(int sz)
{
    if(setSockOpt(SO_RCVBUF, (char*)&sz, int(sizeof(int)), SOL_SOCKET) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setRecvBufferSize] error", errno);
    }
}

int TC_Socket::getRecvBufferSize()
{
    int sz;
    socklen_t len = sizeof(sz);
    if(getSockOpt(SO_RCVBUF, (void*)&sz, len, SOL_SOCKET) == -1 || len != sizeof(sz))
    {
        throw TC_Socket_Exception("[TC_Socket::getRecvBufferSize] error", errno);
    }

    return sz;
}

void TC_Socket::setblock(int fd, bool bBlock)
{
    int val = 0;

    if ((val = fcntl(fd, F_GETFL, 0)) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setblock] fcntl [F_GETFL] error", errno);
    }

    if(!bBlock)
    {
        val |= O_NONBLOCK;
    }
    else
    {
        val &= ~O_NONBLOCK;
    }

    if (fcntl(fd, F_SETFL, val) == -1)
    {
        throw TC_Socket_Exception("[TC_Socket::setblock] fcntl [F_SETFL] error", errno);
    }
}

struct autoClosePipe {
    int fds_[2];
    bool canceled_;
    autoClosePipe(int fds[2]) : canceled_(false) {
        fds_[0] = fds[0];
        fds_[1] = fds[1];
    }
    ~autoClosePipe() {
        if (canceled_) return;
        ::close(fds_[0]);
        ::close(fds_[1]);
    }
    void cancel() {
        canceled_ = true;
    }
};

void TC_Socket::createPipe(int fds[2], bool bBlock)
{
    if(::pipe(fds) != 0)
    {
        throw TC_Socket_Exception("[TC_Socket::createPipe] error", errno);
    }

    autoClosePipe ep(fds);
    setblock(fds[0], bBlock);
    setblock(fds[1], bBlock);
    ep.cancel();
}

vector<string> TC_Socket::getLocalHosts()
{
    vector<string> result;

    TC_Socket ts;
    ts.createSocket(SOCK_STREAM, AF_INET);

    int cmd = SIOCGIFCONF;

    struct ifconf ifc;

    int numaddrs = 10;

    int old_ifc_len = 0;

    while(true)
    {
        int bufsize = numaddrs * static_cast<int>(sizeof(struct ifreq));
        ifc.ifc_len = bufsize;
        ifc.ifc_buf = (char*)malloc(bufsize);
        int rs = ioctl(ts.getfd(), cmd, &ifc);

        if(rs == -1)
        {
            free(ifc.ifc_buf);
            throw TC_Socket_Exception("[TC_Socket::getLocalHosts] ioctl error", errno);
        }
        else if(ifc.ifc_len == old_ifc_len)
        {
            break;
        }
        else
        {
            old_ifc_len = ifc.ifc_len;
        }
    
        numaddrs += 10;
        free(ifc.ifc_buf);
    }

    numaddrs = ifc.ifc_len / static_cast<int>(sizeof(struct ifreq));
    struct ifreq* ifr = ifc.ifc_req;
    for(int i = 0; i < numaddrs; ++i)
    {
        if(ifr[i].ifr_addr.sa_family == AF_INET)
        {
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr[i].ifr_addr);
            if(addr->sin_addr.s_addr != 0)
            {
                char sAddr[INET_ADDRSTRLEN] = "\0";
                inet_ntop(AF_INET, &(*addr).sin_addr, sAddr, sizeof(sAddr));
                result.push_back(sAddr);
            }
        }
    }

    free(ifc.ifc_buf);

    return result;
}


}
