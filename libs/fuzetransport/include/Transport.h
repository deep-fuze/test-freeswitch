//
//  Transport.h
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#ifndef _FUZE_TRANSPORT_H_
#define _FUZE_TRANSPORT_H_

#include "Common.h"
#include "DnsClient.h"
#include "Timer.h"
#include "Util.h"
#include "Secure.h"

namespace fuze {

// Name used on base type string
#define SRC_BASE_TYPE "SrcBaseType"

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

    // Variables added for buffer optimization
    int      appID_;

    // constructor create a new buffer
    //
    NetworkBuffer();

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
    ET_IN_PROGRESS    // notification of failover in process
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
    virtual void OnRateData(void*    /* pContext */,
                            RateType /* type */,
                            uint16_t /* rateKbps */,
                            uint16_t /* count */,
                            uint16_t /* arrivedTime */) {}

    virtual ~ConnectionObserver() {}
};

enum ConnectionType
{
    CT_INVALID      = 0x00,
    CT_UDP          = 0x01, // for UDP client/server
    CT_DTLS_CLIENT  = 0x02,
    CT_DTLS_SERVER  = 0x04,
    CT_BULK_UDP     = 0x08,

    CT_DTLS_TYPE    = (CT_DTLS_CLIENT|CT_DTLS_SERVER),
    CT_DGRAM_TYPE   = (CT_UDP|CT_BULK_UDP|CT_DTLS_CLIENT|CT_DTLS_SERVER),

    CT_TCP          = 0x10, // for TCP client
    CT_TCP_LISTENER = 0x20, // for TCP server
    CT_TLS          = 0x40, // for TLS client
    //CT_TLS_LISTENER - TODO

    CT_STREAM_TYPE  = (CT_TCP|CT_TCP_LISTENER|CT_TLS)
};

const char* toStr(ConnectionType eType);

//-----------------------------------------------------------------------------
// Interface: App --> Transport
//-----------------------------------------------------------------------------
class Connection
{
public:
    typedef fuze_shared_ptr<Connection> Ptr;

    static const uint16_t ICE_UFRAG_LEN = 24;
    static const uint16_t ICE_PWD_LEN   = 24;

    static void GenerateIceCredentials(std::string &ufrag, std::string &pwd);

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

    // if set, processes data on the transceiver thread
    virtual void SetProcessDataSync() = 0;

    // ICE-Lite short-term credential
    virtual void SetLocalIceCredential(const string& rUser, const string& rPwd) = 0;
    virtual void SetRemoteIceCredential(const string& rUser, const string& rPwd) = 0;

    // Set payload type - affects behavior such as timer or thread assignment
    //                    also the QoS tag in network header
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
    virtual bool Send(const uint8_t* buf, size_t size, uint16_t remotePort = 0) = 0;

    // Query the connection info
    virtual bool GetConnectedType(ConnectionType& rType) = 0;
    virtual bool GetLocalAddress(string& rIP, uint16_t& rPort) = 0;
    virtual bool GetRemoteAddress(string& rIP, uint16_t& rPort) = 0;
    virtual void GetLocalIceCredential(string& rUser, string& rPwd) = 0;
    virtual void GetRemoteIceCredential(string& rUser, string& rPwd) = 0;

    // Query the send queue info
    virtual void GetSendQInfo(size_t& rNum, uint32_t& rBufSize) = 0;
    virtual void EnableRateReport(bool flag) = 0;
    virtual void GetSendStat(uint32_t& rCount, int64_t& rBytes) = 0;
    virtual void GetRecvStat(uint32_t& rCount, int64_t& rBytes) = 0;

    // Relevant to UDP sockets used for Video transfer
    // Reset operation is done in the background thread
    // and Allocate is not - therefore there is no way to find out when
    // Those parameters control whether or not the ports were reserved and needs to be released or not
    virtual void EnablePortReservation(bool flag) = 0;
    virtual bool UsePortReservation() = 0;

    // Buffer memory optimization
    virtual NetworkBuffer::Ptr GetBuffer(uint32_t bufSize) = 0;
    virtual NetworkBuffer::Ptr GetBuffer(Buffer::Ptr spBuf) = 0; // shallow copy

    virtual void SetWindowSize(unsigned long windowSize) = 0;

    virtual ~Connection() {}
};

const char* toStr(Connection::PayloadType type);

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
    // Enabling this API won't allow multiple threads to be called into
    // same transport callback. Multi-threading model on transport is
    // different than raw thread pooling architecture. There will be a
    // pool of threads but each connection of transport is assigned with
    // a SINGLE worker thread. This guarantees same benefit as simplified
    // single thread model, meaning you won't see two or more threads called
    // back into same transport callback at the same time. There will be
    // only single dedicated thread work for that callback and other
    // connections will be handled by other work threads at the same time.
    // This requires some synchronization on application code for some area
    // where multiple threads can meet thru different connection callback.
    // The efficiency can be monitored by seeing the queue size of worker
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

    virtual void SetDSCP(Connection::PayloadType type,
                         uint32_t value) = 0;
    virtual void EnableNetServiceType(bool flag) = 0;

    // API made for android where shutdown processing isn't reliable
    virtual void ForceDnsCacheStore() = 0;

    virtual ~Transport() {}

protected:
    Transport();
};

const char* toStrDSCP(uint32_t value);

} // namespace fuze

#endif // _FUZE_TRANSPORT_H_
