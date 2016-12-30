//
//  TransportImpl.h
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TransportImpl__
#define __FuzeTransport__TransportImpl__

#include <Transport.h>
#include <Resource.h>
#include <Prober.h>
#include <Stun.h>
#include <Address.h>
#include <TimerService.h>
#include <set>
#include <queue>

#include <event2/event.h>

#ifdef __ANDROID_API__
#include <netinet/in.h>
#endif

namespace fuze {

using std::set;
using std::queue;
using namespace dns;

//
// Forward declaration
//
class TransportBaseImpl;
class ConnectionImpl;
class Server;
class ProxyConnector;
    
//
// fuze_shared_ptr destructor for Base and Connection
//
void TransportBaseEnded(TransportBaseImpl* p);
void ConnectionEnded(ConnectionImpl* p);
    
//
// constant for better readability
//
#ifndef INVALID_SOCKET
const evutil_socket_t INVALID_SOCKET = -1;
#endif
const int             INVALID_ID     = -1; // Base, Connection, Transceiver, Client
   
typedef fuze_shared_ptr<Server>         ServerPtr;
typedef fuze_shared_ptr<ProxyConnector> ProxyConnectorPtr;

struct PortReserve : public Timer
{
    typedef fuze_shared_ptr<PortReserve> Ptr;
    
    int64_t          timerID_;
    evutil_socket_t  sock_;
    
    virtual void OnTimer(int32_t AppData);
};

class WorkerThread : public Runnable
{
public:
    typedef fuze_shared_ptr<WorkerThread> Ptr;
    
    WorkerThread(const char* pName);
    ~WorkerThread();
    
    void Start();
    void End();
    
    ThreadID_t  ID();
    const char* Name();
    
    void SetWork(ConnectionImpl* pConn);
    
private:

    ConnectionImpl* GetWork();
    
    typedef queue<ConnectionImpl*> WorkQueue;
    
    // Implement Runnable
    virtual void Run();
    
    bool       bActive_;
    bool       bExited_;
    Thread     thread_;
    Semaphore  sem_;
    WorkQueue  queue_;
    MutexLock  qLock_;
};
    
class TransportImpl : public Transport
                    , public Runnable
{
public:
    static TransportImpl* GetInstance();
    virtual ~TransportImpl();
    
    // Transport Interface
    virtual bool Initialized();
    virtual void EnableServerMode(Mode mode = MODE_FW_443);
    virtual void SetNumberOfThread(int numThreads = -1);
    virtual TransportBase::Ptr CreateBase(const char* pName = 0);
    virtual void RegisterTraceObserver(TransportTraceObserver* pObserver,
                                       bool bPrefix = false);
    virtual void DeregisterTraceObserver();
    virtual const char* GetCertificateFingerprint();
    virtual void SetUdpProbe(const string& rAddr, uint16_t port);
    virtual void SetLogLevel(SeverityType eType);
    virtual void RegisterTransportUser(TransportUser* pUser,
                                       TransportUser::Type type);
    virtual void RegisterAkamaiTransport(const string& rRemote,
                                         const string& rAkamai);
    virtual string GetAkamaiMapping(const string& rRemote);
    virtual void   SetMappingInfo(const string& mapInfo);
    virtual string GetMappingInfo();
    
    // Register event
    bool CreateEvent(event*&           rpEvent,
                     evutil_socket_t   sock,
                     short             what,
                     event_callback_fn cb,
                     void*             pArg,
                     uint32_t          timeOut = 0); // in milliseconds
                                                     // default no timeout
    // Query to see whether UDP is blocked or not
    bool IsUdpBlocked();
    
    // Query if application is server (not client)
    bool IsAppServer();
    
    // Get server instance - used by Client objects that
    // represents the firewall blocked traffic
    ServerPtr GetServer();
        
    // Request to reset base/connection/client
    //
    //  The purpose of this interface is to consolidate
    //  resetting logic to libevent thread so that
    //  race condition is addressed among multiple threads
    //
    //  NOTE: pObject option must only be set when we are
    //        returning object back to ResourceMgr
    //        (ie. shared_ptr's custom destructor)
    //
    void RequestReset(Resource::Type eType, int ID, Resource* p = 0);
    
    // Using CURL feature to connect HTTP proxy (which happens synchronously)
    // a separate thread in ProxyConnector waits and gets the final result
    // of the operation. Since internal process is all handled by libevent
    // thread directly, we hand off the logic by requesting post processing.
    void RequestPostConnect(int tcpID);

    // Interfaces for congestion control between bases
    void RequestCongestion(const CongestionInfo& rInfo);
    
    // Proxy Connector is thread handoff where libevent will give its
    // logical control flow of connection to curl flow
    void EnableProxyConnector(bool enabled);
    ProxyConnectorPtr GetProxyConnector();

    void SetCongestionBaseID(TransportBase::Type eType, int baseID);
    
    TimerService::Ptr& GetTimerService();
    
    void ReserveUdpPort(uint16_t port, evutil_socket_t sock, uint32_t holdTime);
    PortReserve::Ptr GetReservedPort(uint16_t port);

    // DNS Cache interface
    void SetDnsCache(Record::List& rList);
    Record::List GetDnsCache(const string& rDomain, Record::Type type);
    void MarkDnsCacheBad(const string& rIPString); // A record only
    void ClearDnsCache();
    
    WorkerThread::Ptr GetWorker(ConnectionImpl* pConn);
    
private:
    TransportImpl();
        
    // Thread Interface
    void Run();
    
    // Create libevent base
    void CreateEventBase();
    void AddWorkerThread(size_t workerId);
    
private:
    
    // internal clean up logic called by libevent thread only
    struct ResetRequest
    {
        Resource::Type  type_;
        int             id_;
        Resource*       pResource_; // pointer to object that is released
    };
    
    bool GetResetRequest(ResetRequest& rResetReq);
    void HandleResetRequest(const ResetRequest& rReq);
    
    // Using CURL proxy connect feature, we hand off the result to libevent thread
    bool GetRequestedTcpID(int& tcpID);
    void HandlePostConnect(int tcpID);

    bool GetCongestionRequest(CongestionInfo& rInfo);
    void HandleCongestionRequest(CongestionInfo& rInfo);
    void NotifyCongestion(TransportBase::Type eType, CongestionInfo& rInfo);    
    
    void PrintQSize();
    
private:
    static TransportImpl*  spInstance_;
    static MutexLock       sLock_;
    
    Thread                 eventThread_;
    event_base*            pEventBase_;   // created in ctor
    bool                   eventActive_;  // event state
    bool                   loopexit_;     // flag for at-most-once on loopexit
    
    Semaphore              semaphore_;    // libevent thread to wait
    
    MutexLock              lock_;         // protect baseSet_, resetQ_, proxyQ_, loopexit_
    set<int>               baseSet_;      // track of bases
    
    queue<ResetRequest>    resetQ_;       // queues reset requests
    queue<int>             proxyQ_;       // proxy connect process request
    queue<CongestionInfo>  congestQ_;     // congestion notification
    
    Prober::Ptr            spProber_;
    ServerPtr              spServer_;     // Server that listens to port 443
    bool                   bServerMode_;  // added so that don't listen on 443 for Vidyo
    ProxyConnectorPtr      spProxy_;      // CURL wrapper for using HTTP Proxy
    
    TimerService::Ptr      spTimerService_;
    
    int                    baseID_[TransportBase::END];    
    TransportUser*         userList_[TransportUser::END_USER];

    string                 mapInfo_;      // mapping info for sshub to identify user
    
    map<string, string>    akamaiMap_;
    MutexLock              mapLock_;
    
private: // port reservation
    typedef map<uint16_t, PortReserve::Ptr> PortMap;
    
    PortMap                mapPort_;
    MutexLock              portLock_;
    
private: // DNS Cache
    typedef map<string, Record::List> DnsRecordMap;
    
    DnsRecordMap           dnsCache_[Record::MAX_NUM];
    MutexLock              dnsLock_;
    
private: // Thread workers
    
    vector<WorkerThread::Ptr> threadQ_;
    size_t                    qIndex_;
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__TransportImpl__) */
