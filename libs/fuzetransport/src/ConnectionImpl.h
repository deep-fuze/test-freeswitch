//
//  ConnectionImpl.h
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 Tim Na. All rights reserved.
//

#ifndef __FuzeTransport__ConnectionImpl__
#define __FuzeTransport__ConnectionImpl__

#include <TransportImpl.h>
#include <Transceiver.h>
#include <Resource.h>
#include <Thread.h>
#include <atomic>
#include <queue>

namespace fuze {

using std::ostringstream;
using std::queue;
using core::RawMemory;
    
struct StatData
{
    static const uint16_t MAX_NUM = 200;

    uint16_t     data_[MAX_NUM];
    uint16_t     index_;
    uint32_t     seq_;
    const char*  pUnit_;
    
    StatData(const char* pUnit);
    
    void Clear();
    void SetData(uint16_t data);
    bool Display(ostringstream& rLog,
                 const char*    pLog,
                 const char*    pPrefix);
};
    
struct Stat
{
    static const int64_t  PERIOD      = 1000; // 1 seconds
    static const uint16_t DISPLAY_CNT = 10;
    static const uint8_t  TYPE_SEND   = 0;
    static const uint8_t  TYPE_RECV   = 1;
    
    uint32_t  count_;
    int64_t   bytes_;
    int64_t   bytes2_; // track intermittent usage
    int64_t   totalBytes_;
    int64_t   lastTime_;
    char      log_[64];
    
    StatData  local_;       // local bandwidth
    StatData  remote_;      // remote bandwidth
    StatData  sendQ_;       // sendQ_ size
    StatData  sendBuf_;     // buffer size to send
    StatData  sendRetry_;   // retry (full socket buffer)
    StatData  arrival_;     // jitter of receiving stat
    int64_t   lastArrival_; // timestamp of remote report
    int64_t   lastSent_;    // timestamp of our report
    
    ConnectionImpl* pConn_; // sendStat on sendQ Info
    
    // set ConnectionImpl for report
    Stat(ConnectionImpl* pConn = 0);
    
    void Clear();
    
    // Add bytes so that we can measure usage
    // returns rate in kbps if available
    // -1 means rate is not calculated yet
    int AddBytes(uint32_t bytes);
};

const uint16_t RTP_TIMEOUT  = 5000;  // 5 seconds
const uint16_t RTCP_TIMEOUT = 30000; // 30 seconds
const uint16_t READ_TIMEOUT = 15000; // 15 seconds
    
class ConnectionImpl : public Connection
                     , public Resource
{
public:
    enum State
    {
        CONNECTED  = 0x01,
        TERMINATED = 0x02
    };
    
    explicit ConnectionImpl(int connID);
    virtual ~ConnectionImpl();

    // Connection Interface
    virtual void RegisterObserver(ConnectionObserver* pObserver);
    virtual void RegisterObserver(ConnectionObserver::WPtr wPtr);
    virtual void DeregisterObserver();
    virtual void SetName(const char* pName);
    virtual bool SetAppContext(void* pContext);
    virtual bool SetLocalAddress(const string& IP, uint16_t port);
    virtual bool SetRemoteAddress(const string& IP, uint16_t port);
    virtual void SetWYSWYGMode();
    virtual void SetLocalIceCredential(const string& rUser, const string& rPwd);
    virtual void SetRemoteIceCredential(const string& rUser, const string& rPwd);
    virtual void SetPayloadType(uint32_t flag);
    virtual void SetRemoteAddressPerBuffer(bool enabled);
    virtual bool Start(ConnectionType eType, int mode = 0);
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const uint8_t* buf, size_t size);
    virtual bool GetConnectedType(ConnectionType& rType);
    virtual bool GetLocalAddress(string& rIP, uint16_t& rPort);
    virtual bool GetRemoteAddress(string& rIP, uint16_t& rPort);
    virtual void GetSendQInfo(size_t& rNum, uint32_t& rBufSize);
    virtual void EnableRateReport(bool flag);
    virtual void GetSendStat(uint32_t& rCount, int64_t& rBytes);
    virtual void GetRecvStat(uint32_t& rCount, int64_t& rBytes);
    virtual void EnablePortReservation(bool flag);
    virtual bool UsePortReservation();
    virtual NetworkBuffer::Ptr GetBuffer(uint32_t bufSize);
    virtual NetworkBuffer::Ptr GetBuffer(Buffer::Ptr spBuf);
    
    // Addtional internal API
    const Address& GetLocalAddress();
    const Address& GetRemoteAddress();
    
    bool IsValidRemote(const Address& rAddr) const { return (rAddr == remote_ || rAddr == b4akamaiMap_); }
    
    void GetLocalIceCredential(string& rUser, string& rPwd);
    void GetRemoteIceCredential(string& rUser, string& rPwd);

    bool IsPayloadType(PayloadType flag) const { return 0 != (flag & payloadType_); }
    bool IsFallback();
    bool IsRemotePerBuffer() const { return bRemotePerBuf_; }
    
    // Resource Interface
    virtual void Reset();
    
    // Set association with TransportBase
    void SetBaseID(int baseID);
    
    // pass down the name to transceiver
    const char* GetName();
    
    // Retrieve ID
    int BaseID();
    
    // interface to initialize with existing socket - TCP only for now
    // on newly created incoming TCP connection
    bool Initialize(ConnectionType  eType,
                    evutil_socket_t sock,
                    bool            overTLS = false);
    
    // Send data/event to Application
    void OnData(Buffer::Ptr spBuffer);
    void OnEvent(EventType eType, const char* pReason = "");
    void OnRateData(RateType type, uint16_t rate, uint16_t delta);
    
    // Calculating bandwidth usage rate
    uint32_t OnBytesSent(uint32_t bytesSent);
    uint32_t OnBytesRecv(uint32_t bytesRecv);
    void ClearStat();
    void OnStatReceived(Buffer::Ptr spStat);
    void OnMapReceived(Buffer::Ptr spMap);
    
    // Statistics
    uint32_t GetSendRetryCount();
    
    // callback from transceiver in case of connection timeout
    void OnTransceiverTimeout();
    
    // Firewall traversal
    // since we connect using 443, we need to tell what the original
    // port we were trying so that server can map it into right
    // context in its processing
    ConnectionType GetOriginalConnectionType() const;
    bool GetOriginalRemoteAddress(string& rRemote, uint16_t& rPort);
    void ReplaceTransceiver(Transceiver* pTrans);

    // logic to handle connection failure due to firewall
    bool Failover(bool bRetrySameType = false);
    bool RetryIfNetworkChanged();
    
    bool InState(State flag);
    void SetState(State flag);
    
private:
    static const int RETRY_BEFORE_FAIL = 5;
    
    int                      baseID_;        // ID of TransportBase that owns this
    char                     name_[16];      // debuging purpose
    void*                    pAppContext_;
        
    Address                  local_;
    Address                  remote_;
    string                   domainRemote_;  // case where DNS is not allowed
    
    Transceiver*             pTransceiver_;
    MutexLock                transLock_;     // sync between app and transport threads
    
    uint16_t                 state_;         // connection state
    
    ConnectionObserver*      pObserver_;
    MutexLock                conLock_;       // lock for pObserver
    ConnectionObserver::WPtr wpObserver_;
    
    // firewall traversal related variables
    bool                     bFallback_;     // to fallback or not
    ConnectionType           origType_;      // original connection type
    Address                  origRemote_;    // original remote address
    bool                     removeBinding_; // flag to remeber that
                                             // we created binding with Server
    bool                     bWYSWYG_;       // enable framing for TCP
    
    uint32_t                 payloadType_;
    
    Address                  b4akamaiMap_;   // Sometimes akamai sends original src IP
                                             // Prevent their bug to mess up the client
    
    bool                     bRemotePerBuf_;
    bool                     bReservePort_;
    
private: // ICE-lite short-term credential
    string                   localUser_;
    string                   localPassword_;
    string                   remoteUser_;
    string                   remotePassword_;
    MutexLock                lock_;
    
private: // statistics for send/recv
    Stat                     sendStat_;
    Stat                     recvStat_;
    bool                     bRateReport_;
    
    StatData                 timeStat_;      // statistics to reduce log
    StatData                 delayStat_;     // on app delay
    int64_t                  lastDelayStat_;
    
public: // Interface for thread to enter and work
    
    bool ServiceQueue(ThreadID_t workerID);
    
private: // separate work thread for heavy lifting such as video/screenshare
    
    struct EventData
    {
        EventType  type_;
        string     reason_;
    };
    
    struct RateData
    {
        RateType   type_;
        uint16_t   rate_;
        uint16_t   delta_;
    };
    
    void DeliverData(Buffer::Ptr spBuffer);
    void DeliverEventData(EventData& rEvent);
    void DeliverRateData(RateData& rRate);
    
    ThreadID_t               workerId_;
    WorkerThread::Ptr        spWorker_; // shared thread worker
    
    queue<Buffer::Ptr>       workQ_;
    queue<EventData>         eventQ_;
    queue<RateData>          rateQ_;
    MutexLock                qLock_;
    
private:
    enum QueueSizeType
    {
        BUFFER_SHELL,
        SIZE_64, SIZE_256, SIZE_1024, SIZE_2048,
        SIZE_32000, SIZE_65000, SIZE_262000,
        MAX_QUEUE_SIZE
    };

    typedef queue<void*> BufferQueue;
    
    static uint32_t SizeArray[MAX_QUEUE_SIZE];
    
    static void         HandleReleasedBuffer(NetworkBuffer* pBuf);
    static void         HandleReleasedMemory(RawMemory* pMem);
    
    void                AddBuffer(NetworkBuffer* pBuf);
    void                AddMemory(RawMemory* pMem);
    QueueSizeType       GetSizeType(uint32_t bufSize);
    NetworkBuffer::Ptr  GetBufferShell();
    
    BufferQueue              bufPool_[MAX_QUEUE_SIZE];
    MutexLock                poolLock_;
    
    std::atomic<uint16_t>    bufNum_;
    std::atomic<uint16_t>    bufAlloc[MAX_QUEUE_SIZE];
};

//
// The purpose of NoTransceiver is to have a valid pointer for cleaner code
//
class NoTransceiver : public Transceiver
{
public:
    static NoTransceiver* GetInstance() { return &sInstance_; }
    
    virtual bool Start() { return false; }
    virtual bool Send(Buffer::Ptr spBuffer) { return false; }
    virtual bool Send(const uint8_t* buf, size_t size) { return false; }
    virtual void SetConnectionID(int connID) {}
    
    virtual void           Reset()    {}
    virtual int            TransID()  { return -1; }
    virtual ConnectionType ConnType() { return CT_INVALID; }
    
private:
    NoTransceiver() : Transceiver(INVALID_ID) {}
    static NoTransceiver sInstance_;
};

bool is_end_event(EventType type);

void fuze_srtp_init(); // initialize srtp library
    
} // namespace fuze
    
#endif /* defined(__FuzeTransport__ConnectionImpl__) */
