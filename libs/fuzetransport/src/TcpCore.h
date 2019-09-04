//
//  TcpCore.h
//  FuzeTransport
//
//  Created by Tim Na on 1/21/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TcpCore__
#define __FuzeTransport__TcpCore__

#include <TransportImpl.h>
#include <queue>

namespace fuze {
    
using std::queue;

class TcpCore;
    
class RateLimiter
{
public:
    RateLimiter(TcpCore* pCore);

    inline virtual ~RateLimiter()
    {
    }

    void Reset(); // reset to original state with TcpCore
    
    void SetMTU(long mtu);
    void ClearEvent(); // clear the usage of limiter for next use
    
    bool IsOn();
    bool IsLimiting(); // indicate if this is being used
    
    // should be executed in sequence of following order
    long GetAllowedBytes();
    void SetSentBytes(long sent);
    bool Continue();

    static const uint32_t RATE_PERIOD = 10;
    static const long     MTU_SIZE    = 8000;
    
private:
    static void OnRateEvent(evutil_socket_t socket,
                            short           what,
                            void*           pArg);
    TcpCore*  pCore_;
    event*    pRateEvent_;
    bool      rateAdded_;
    
    long      mtu_;
    long      allowedBytes_;
    int64_t   startTime_;
};
    
class TcpCoreUser
{
public:
    // CoreUser needs to provide a socket to work
    virtual evutil_socket_t Socket() = 0;
    
    // OnDataReceived
    //  @param   spBuf Buffer that holds the data
    //  @return  Application needs to return the
    //           number of bytes it consumed
    virtual uint32_t OnDataReceived(Buffer::Ptr spBuf) = 0;
    
    // Notifying User on bytes sent/received
    virtual void OnBytesSent(uint32_t bytesSent) = 0;
    virtual void OnBytesRecv(uint32_t bytesRecv) = 0;
    
    // Invoked when far end disconnects us
    virtual void OnDisconnect() = 0;
    
    // Invoked on error cases
    virtual void OnReadError(int error) = 0;
    virtual void OnWriteError(int error) = 0;
    
    // Invoked on read timeout on every timeout value set by User
    virtual void OnReadTimeout() = 0;
    
    inline virtual ~TcpCoreUser()
    {
    }
};

//
// TcpCore
//
// Originally this was part of TcpTransceiver but
// as Firewall Server required similar feature
// it made a sense to refactor the common feature
// and this is the result of the commonality
//
class TcpCore
{
public:
    TcpCore(TcpCoreUser& rUser);
    virtual ~TcpCore();

    // trigger data receiving
    bool StartReceive();
    
    // queue up the data to send
    void Send(Buffer::Ptr spBuf);
    
    // Reset the TcpCore
    void Reset();
    
    void SetReadTimeout(uint16_t timeout);
    void SetMaxBandwidth(uint16_t maxKbps);
    
    void     GetSendQInfo(size_t& rNum, uint32_t& rBufSize);
    uint32_t GetSendRetryCount();
    
public: // members to be exposed to make life easier
    char    log_[64]; // debug purpose
    event*  pReadEvent_;
    event*  pWriteEvent_;
    
private:
    static void OnLibEvent(evutil_socket_t socket,
                           short           what,
                           void*           pArg);
    
    void OnWriteEvent();
    void OnReadEvent();
    void OnTimeoutEvent();
    
    void ResetReadBuffer();
    
    // the MTU size for TcpTransceiver is 65KB as
    // different TcpState only allow 2 bytes of length
    // field (UdpOverTcp, DataOverTls)
    static const uint32_t BUFFER_SIZE    = 32000;
    static const uint32_t BUF_SIZE_LIMIT = 65000; // 65KB
    
    // TcpCore needs to be have strong association
    // with its user that it insists on using
    // reference of TcpCoreUser
    TcpCoreUser&        rCoreUser_;
    
    // queue to send TCP stream
    queue<Buffer::Ptr>  sendQ_;
    MutexLock           qlock_;       // sendQ_, writeAdded_, pWriteEvent_
    bool                writeAdded_;  // keep track of event added or not
    Buffer::Ptr         sendBuf_;
    uint32_t            byteSent_;
    
    Buffer::Ptr         recvBuf_;
    uint32_t            byteRecv_;

    uint16_t            readTimeout_; // for detecting network switch
    
private: // Leaky bucket
    RateLimiter         rateLimiter_;
    friend class        RateLimiter;
    
private: // statistics info
    uint32_t            sendQSize_;
    uint32_t            sendBufSize_;
    uint32_t            sendRetryCnt_;
};

void set_available_size(Buffer::Ptr spBuf);
    
} // namespace fuze
    
#endif /* defined(__FuzeTransport__TcpCore__) */
