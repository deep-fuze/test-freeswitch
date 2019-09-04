//
//  Transport.h
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#ifndef _FUZE_TRANSPORT_H_
#define _FUZE_TRANSPORT_H_

#include <string>
#include <vector>
#include <map>
#include <list>

using std::string;
using std::vector;
using std::list;
using std::map;

#ifdef NO_FUZECORE
#include <Buffer.h>
#else
#include <fuze/core/Buffer.h> // fuze_shared_ptr header in fuzememory.h
#endif

namespace fuze {

//-----------------------------------------------------------------------------
//  Network Buffer
//
//   This is used when data is bubbled up to applicatio and optionally
//   application can downcast to retrieve the remote address info
//-----------------------------------------------------------------------------
using core::Buffer;

struct NetworkBuffer : public Buffer
{
    typedef fuze_shared_ptr<NetworkBuffer> Ptr;
    
    // FreeSwitch cares about remote IP/Port pair that we will create
    // derived off Buffer to hold those information
    string   remoteIP_;
    uint16_t remotePort_;
    bool     changed_;
    
    // constructor create a new buffer
    //
    NetworkBuffer(uint32_t size);
    
    // constructor for creating a "shallow copy" of buffer into network buffer
    //
    //   Use case: when we receive data from network,
    //             its data will be linked (not copied)
    //
    NetworkBuffer(Buffer::Ptr spRecv);
};

enum EventType
{
    ET_NONE,
    ET_CONNECTED,
    ET_DISCONNECTED,
    ET_REFUSED,       // remote is not reachable and will trigger failover
    ET_FAILED,        // Connection failed and can't connect to far end
    ET_IN_PROGRESS,   // notification of failover in process
    
    ET_APP_DELAY      // Notify app that it is delaying transport work
};

const char* toStr(EventType type);

enum RateType
{
    RT_LOCAL_SEND,
    RT_LOCAL_RECV,
    RT_REMOTE_SEND,
    RT_REMOTE_RECV
};

const char* toStr(RateType type);
    
//-----------------------------------------------------------------------------
// Interface: App <-- Transport
//-----------------------------------------------------------------------------
class ConnectionObserver
{
public:
    typedef fuze_weak_ptr<ConnectionObserver>   WPtr;
    typedef fuze_shared_ptr<ConnectionObserver> Ptr;
    
    virtual void OnDataReceived(void* pContext, Buffer::Ptr spBuffer) = 0;
    virtual void OnEvent(void* pContext, EventType eType, const string& rReason) = 0;
    
    // Statistic report from Connection
    //
    // rateKbps    : indicates bandwidth rate
    // arrivedTime : indicates report data arrival time (expected every second)
    //
    virtual void OnRateData(RateType /*type*/,
                            uint16_t /*rateKbps*/,
                            uint16_t /*arrivedTime*/) {}
    
    virtual ~ConnectionObserver() {}
};

enum ConnectionType
{
    CT_INVALID      = 0x00,
    CT_UDP          = 0x01, // for UDP client/server
    CT_DTLS_CLIENT  = 0x02,
    CT_DTLS_SERVER  = 0x04,
    
    CT_DTLS_TYPE    = (CT_DTLS_CLIENT|CT_DTLS_SERVER),
    CT_DGRAM_TYPE   = (CT_UDP|CT_DTLS_CLIENT|CT_DTLS_SERVER),
    
    CT_TCP          = 0x10, // for TCP client
    CT_TCP_LISTENER = 0x20, // for TCP server
    CT_TLS          = 0x40, // for TLS client
    //CT_TLS_LISTENER - TODO

    CT_STREAM_TYPE  = (CT_TCP|CT_TCP_LISTENER|CT_TLS)
};

const char* toStr(ConnectionType eType);

enum PriorityType
{
    PT_BESTEFFORT,
    PT_BACKGROUND,
    PT_EXCELLENTEFFORT,
    PT_AUDIOVIDEO,
    PT_VOICE,
    PT_CONTROL,
    PT_MAX_PRIORITY
};

//-----------------------------------------------------------------------------
// Interface: App --> Transport
//-----------------------------------------------------------------------------
class Connection
{
public:
    typedef fuze_shared_ptr<Connection> Ptr;
    
    // Register ConnectionObserver
    virtual void RegisterObserver(ConnectionObserver* pObserver) = 0;
    virtual void RegisterObserver(ConnectionObserver::WPtr wPtr) = 0;
    
    // De-register ConnectionObserver for raw pointer only
    virtual void DeregisterObserver() = 0;
    
    // Set debug name for better connection loggin
    virtual void SetName(const char* pName) = 0;
    virtual const char* GetName() = 0;
    
    // Whatever App set here will be returned on callback
    virtual bool SetAppContext(void* pContext) = 0;
    
    // Local address should be set first if we want sending packet to
    // have this local address. This implies we are going to receive.
    virtual bool SetLocalAddress(const string& IP, uint16_t port) = 0;
    
    // This implies we are going to send to certain address.
    // Here connection probing will start to decide to see what kind of
    // connection is available for us to use. If this is not set and
    // send is called, whatever address we received from far end
    // will be set as RemoteAddress - firewall traversal from server
    virtual bool SetRemoteAddress(const string& IP, uint16_t port) = 0;
    
    // Set 'WHAT YOU SEND is WHAT YOU GET' mode
    // In UDP, you normally send a data chunk and you will get whole
    // chunk at a time.  It is not so in TCP that this mode will force
    // UDP like transmission in TCP where application don't have to
    // worry about fragmentation of incoming data
    //
    virtual void SetWYSWYGMode() = 0;
    
    // Set the priority for the connection
    virtual void SetPriority(PriorityType priority) = 0;

    // ICE-Lite short-term credential
    virtual void SetLocalIceCredential(const string& rUser, const string& rPwd) = 0;
    virtual void SetRemoteIceCredential(const string& rUser, const string& rPwd) = 0;
    
    // Set payload type - affects behavior such as timer or thread assignment
    enum PayloadType
    {
        STUN  = 0x0001,
        RTP   = 0x0002,
        RTCP  = 0x0004,
        SIP   = 0x0008,
        AUDIO = 0x0010,
        VIDEO = 0x0020,
        SS    = 0x0040
    };
    virtual void SetPayloadType(uint32_t flag) = 0;
    
    // Set remote address by network buffer's remote address
    // primary used for UDP server that handles multiple clients
    virtual void SetRemoteAddressPerBuffer(bool enabled) = 0;
        
    // Start setting up the connection with eType specified and mode
    static const int NO_FALLBACK    = 0x0001;
    static const int FORCE_FUZE_TLS = 0x0002;
    
    virtual bool Start(ConnectionType eType, int mode = 0) = 0;
    
    // There may be some delay to send data
    virtual bool Send(Buffer::Ptr spBuffer) = 0;
    
    // Query the connection info
    virtual bool GetConnectedType(ConnectionType& rType) = 0;
    virtual bool GetPriority(PriorityType &rPriority) = 0;
    virtual bool GetLocalAddress(string& rIP, uint16_t& rPort) = 0;
    virtual bool GetRemoteAddress(string& rIP, uint16_t& rPort) = 0;
    
    // Query the send queue info
    virtual void GetSendQInfo(size_t& rNum, uint32_t& rBufSize) = 0;
    virtual void EnableRateReport(bool flag) = 0;
    
    virtual ~Connection() {}
};

typedef map<string, string> CongestionInfo;
    
//-----------------------------------------------------------------------------
// Interface: App <-- Transport
//-----------------------------------------------------------------------------
class BaseObserver
{
public:
    typedef fuze_weak_ptr<BaseObserver>   WPtr;
    typedef fuze_shared_ptr<BaseObserver> Ptr;
    
    // New Connection spawned from listening TCP connection
    virtual void OnNewConnection(Connection::Ptr spNewConnection) = 0;
    virtual void OnCongestion(const CongestionInfo& rInfo) = 0;

    virtual ~BaseObserver() {}
};

//-----------------------------------------------------------------------------
// Interface: App --> Transport
//-----------------------------------------------------------------------------
class TransportBase
{
public:
    typedef fuze_shared_ptr<TransportBase> Ptr;

    enum Type { NONE, AUDIO, SCREEN_SHARE, VIDEO, END };
    
    // Enables multiple worker threads to come up in OnDataReceived.
    // It is application's responsibility to prevent race condition.
    // Default is one thread per connection
    virtual void Initialize(int numOfThreads = 1) = 0;
    
    // Register BaseObserver
    virtual void RegisterObserver(BaseObserver* pObserver) = 0;
    virtual void RegisterObserver(BaseObserver::WPtr wPtr) = 0;
    
    // De-register BaseObserver for raw pointer only
    virtual void DeregisterObserver() = 0;
    
    // Setting the Application Priority
    virtual void SetType(Type eType) = 0;
    
    // Application needs to make sure that observer lasts more than connection
    // only first 4 character is taken for logging purpose on pName
    virtual Connection::Ptr CreateConnection(const char* pName = 0) = 0;
    
    // Interface for App to notify transport which may trigger other 
    // applications to throttle their data
    virtual void NotifyCongestion(CongestionInfo& rInfo) = 0;
    
    virtual ~TransportBase() {}
};

const char* toStr(TransportBase::Type eType);
    
TransportBase::Type GetSrcBaseType(const CongestionInfo& rInfo);
    
enum SeverityType
{
    LEVEL_MAX   = 5,
    LEVEL_DEBUG = 4,
    LEVEL_MSG   = 3,
    LEVEL_WARN  = 2,
    LEVEL_ERROR = 1
};

//-----------------------------------------------------------------------------
// Interface: App <-- Transport
//-----------------------------------------------------------------------------
class TransportTraceObserver
{
public:
    virtual void OnTransportTrace(SeverityType eType, const char* pLog) = 0;

    virtual ~TransportTraceObserver() {}
};

//-----------------------------------------------------------------------------
// TransportUser
//
//  Transport is singleton that other singleton users need to coordinate
//  shutdown process.  RegisterTransportUser so that it will be done in order
//-----------------------------------------------------------------------------
class TransportUser
{
public:
    enum Type
    {
        FUZE_SIP,
        FUZE_SIP_RSR_MGR,
        TRANSPORT_RSR_MGR,
        END_USER
    };
    
    virtual ~TransportUser() {}
};

const char* toStr(TransportUser::Type type);
    
//-----------------------------------------------------------------------------
// Class: Transport 
//    
//  Singleton that is available commonly to all applications 
//-----------------------------------------------------------------------------
class Transport
{
public:
    static Transport* GetInstance();
    
    // Use fuze log from fuze::core
    static void EnableFuzeLog();
    
    // Indicate if transport is initialized correctly
    //
    virtual bool Initialized() = 0;
    
    enum Mode { MODE_FW_443, MODE_ONLY };
    
    // Indicates this transport is used by Server and
    // FuzeTransport needs to listen to port 443 for
    // NAT/firewall traversal feature with clients
    //
    virtual void EnableServerMode(Mode mode = MODE_FW_443) = 0;
    
    // Set number of worker thread to use via Connection
    //
    //  input -1 will create as many as CPU cores are available
    //
    virtual void SetNumberOfThread(int numThreads = -1) = 0;
    
    // Application creates a base that represents its
    // App context within transport
    //
    //  pName : only first 8 character is taken for logging purpose
    //
    virtual TransportBase::Ptr CreateBase(const char* pName = 0) = 0;
 
    // Register TraceObserver
    // if prefix is true, then time and level will be included in string
    virtual void RegisterTraceObserver(TransportTraceObserver* pObserver,
                                       bool bPrefix = false) = 0;
    
    // De-register TraceObserver
    virtual void DeregisterTraceObserver() = 0;    
    
    // Get Fingerprint of Fuze certificate
    virtual const char* GetCertificateFingerprint() = 0;
    
    // set UDP Probing address
    //  - rAddr can be IP or domain
    virtual void SetUdpProbe(const string& rAddr, uint16_t port) = 0;
    
    // set log level
    virtual void SetLogLevel(SeverityType eType) = 0;

    // To determine destruction sequences of singleton application
    virtual void RegisterTransportUser(TransportUser* pUser,
                                       TransportUser::Type type) = 0;
    
    // Experiment with Akamai
    virtual void RegisterAkamaiTransport(const string& rRemote,
                                         const string& rAkamai) = 0;

    virtual string GetAkamaiMapping(const string& rRemote) = 0;
    
    // used for now as debug string to map user in meeting
    virtual void   SetMappingInfo(const string& mapInfo) = 0;
    virtual string GetMappingInfo() = 0;
    
    virtual ~Transport() {}
  
protected:
    Transport();
};

namespace proxy {
    
    enum Type { NONE, HTTP, SOCKS };
    
    const char* toStr(Type type);
    
    // set Proxy Info for proxy traversal
    //
    //   Address in form of "IP:Port"
    //   Authentication in form of "username:password"
    //
    void SetInfo(const char*  pProxyAddres,
                 const char*  pCredential,
                 Type         type);
    
    // get Proxy Info - interim solution for legacy RTP Proxy
    //
    void GetInfo(string& rProxy,
                 string& rCrednetial,
                 Type&   rType);
} // namespace proxy
    
//-----------------------------------------------------------------------------
// helper method
//-----------------------------------------------------------------------------
//
// Return empty string when local IP address is not
// available yet due to network change
//
// by default use google's public 8.8.8.8 as remote address to connect
string GetLocalIPAddress(const char* pRemoteAddr = "8.8.8.8");

// Check whether this is IP address or domain
bool     IsThisIP(const char* pAddress);
uint32_t GetIPNumber(const char* pIP);
    
//
// checking the port can be binded or not
// if pIP is 0, then INADDR_ANY is used to test
//
bool IsUdpPortAvailable(uint16_t port, const char* pIP = 0);
bool IsTcpPortAvailable(uint16_t port, const char* pIP = 0);
    
//
// Reserve a UDP port for later use upto given holdTime in milliseconds
// if application doesn't use the port, it will be released after that time
//
bool ReserveUdpPort(uint32_t holdTimeMs, uint16_t port, const char* pIP = 0);
void ReleaseUdpPort(uint16_t port);
    
//
// Get current time in milliseconds using platform API for performance
//
int64_t GetTimeMs();

// Hash by MD5
void HashByMD5(uint8_t* pBuf, uint32_t bufLen, uint8_t* digest);
string MD5Hex(uint8_t* digest);
    
//
// Timer interface
//
class Timer
{
public:
    typedef fuze_shared_ptr<Timer> Ptr;
    typedef fuze_weak_ptr<Timer>   WPtr;
    
    virtual void OnTimer(int32_t AppData) = 0;
    
    virtual ~Timer() {}
};

// macro hack to debug where timer is started
#define StartTimer(A, B, C) StartTimerEx(A, B, C, __FILE__, __LINE__)
    
int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line);
int64_t StartTimerEx(Timer* pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line);
    
void    StopTimer(Timer::Ptr pTimer, int64_t handle);
void    StopTimer(Timer* pTimer, int64_t handle);
    
//
// Perform DNS lookup on domain address
//
string         TranslateToIP(const string& rAddress);
vector<string> TranslateToIPs(const string& rAddress);
    
namespace dns {
    
    struct Record
    {
        typedef fuze_shared_ptr<Record> Ptr;
        typedef std::list<Ptr>          List;
        
        enum Type { A, SRV, NAPTR, MAX_NUM };
        
        string    domain_;
        uint32_t  type_;
        uint32_t  class_;
        uint32_t  ttl_;
        int64_t   expire_; // added to track time to be expired
        
        virtual ~Record() {}
    };
    
    struct A : public Record
    {
        typedef fuze_shared_ptr<A> Ptr;
        
        string  hostName_;
    };
    
    struct SRV : public Record
    {
        typedef fuze_shared_ptr<SRV> Ptr;
        
        uint32_t  priority_;
        uint32_t  weight_;
        uint32_t  port_;
        string    name_;
    };
    
    struct NAPTR : public Record
    {
        typedef fuze_shared_ptr<NAPTR> Ptr;
        
        uint32_t  order_;
        uint32_t  pref_;
        string    flag_;
        string    services_;
        string    regexp_;
        string    replacement_;
    };
    
    class Resolver
    {
    public:
        typedef fuze_shared_ptr<Resolver> Ptr;
        
        static void Init();
        static void Terminate();
        
        static Ptr  Create();
        
        virtual Record::List Query(const string& rDomain,
                                   Record::Type  type) = 0;
        virtual ~Resolver() {}
    };

    void MarkAsBadCache(const string& rAddress);
    void ClearCache();
    void PrintRecord(const dns::Record::Ptr& rspRec);
    
    const char* toStr(Record::Type type);
    
} // namespace dns

} // namespace fuze

#endif // _FUZE_TRANSPORT_H_
