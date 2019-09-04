//
//  TransportImpl.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <Server.h>

#include <event2/thread.h> // libevent for multithreading support
#include <stdlib.h>        // for atexit()
#include <sstream>
#include <openssl/ssl.h>
#include <ProxyConnector.h>
#include <TcpTransceiver.h> // to continue processing with ProxyConnector

#ifdef WIN32
#include <ws2ipdef.h> // for INET_ADDRSTRLEN
#else
#include <unistd.h> // check CPU #
#endif

#ifdef __linux__
#include <string.h>
#endif

#include <DnsResolver.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

//
// this is required when application happens to be a global or
// static variable where we can't control the order the
// destruction. gb_process_exiting will be set to true to
// indicate that application is in process of exiting and
// we shouldn't be servicing anymore
//
namespace { bool gb_process_exiting = false; }

namespace fuze {

// this is to avoid the problem with ResourceMgr which may be
// deleting at the same time when libevent is processing the
// reset event at the end of program execution
void fuze_transport_at_exit()
{
    _MLOG_("app is exiting");
    delete TransportImpl::GetInstance();
    gb_process_exiting = true;
}
    
TransportImpl* TransportImpl::spInstance_;
MutexLock      TransportImpl::sLock_;
 
void event_log_cb(int severity, const char* msg)
{
    switch (severity)
    {
    case EVENT_LOG_DEBUG: DEBUG_OUT(LEVEL_DEBUG, AREA_LIB, msg); break;
    case EVENT_LOG_MSG:   DEBUG_OUT(LEVEL_MSG,   AREA_LIB, msg); break;
    case EVENT_LOG_WARN:  DEBUG_OUT(LEVEL_WARN,  AREA_LIB, msg); break;
    case EVENT_LOG_ERR:   DEBUG_OUT(LEVEL_ERROR, AREA_LIB, msg); break;
    }
}
    
// Destructor for TransportBaseImpl
void TransportBaseEnded(TransportBaseImpl* p)
{
    if (gb_process_exiting) return;
    
    int base_id = p->ID();
    
    MLOG("Destructor [b" << base_id << "] called");
    
    // deregister observer in case app didn't do it
    p->DeregisterObserver();
    
    TransportImpl::GetInstance()->RequestReset(Resource::BASE, base_id, p);
}

void ConnectionEnded(ConnectionImpl* p)
{
    if (gb_process_exiting) return;
    
    int conn_id = p->ID();
    
    MLOG("Destructor [c" << conn_id << "] called");

    p->DeregisterObserver();    
    
    TransportImpl::GetInstance()->RequestReset(Resource::CONNECTION, conn_id, p);
}
    
TransportImpl* TransportImpl::GetInstance()
{
    if (gb_process_exiting) return 0;
    
    if (!spInstance_) {
        MutexLock scoped(&sLock_);
        if (!spInstance_) {
            // not only this MLOG is printing log but also
            // initializing static instance of debug out.
            // this will prevent race condition that can
            // corrupt static initization of debug out as
            // we are doing it while creating singleton
            MLOG("initializing FuzeTransport");
            TransportImpl* p = new TransportImpl;
            spInstance_ = p;
        }
    }
    
    return spInstance_;
}
    
TransportImpl::TransportImpl()
    : eventThread_(this, "Transport")
    , pEventBase_(0)
    , eventActive_(false)
    , loopexit_(false)
    , bServerMode_(false)
    , spProber_(new Prober)
    , qIndex_(0)
{
#ifdef WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data) != 0) {
        ELOG("Failed to WSAStartup");
    }
    
    if (evthread_use_windows_threads() == -1) {
        ELOG("Failed to set windows thread on libevent");
    }
#else
    if (evthread_use_pthreads() == -1) {
        ELOG("Failed to set pthread on libevent");
    }
#endif
    
#ifdef DEBUG
    event_enable_debug_mode();
#endif

    // initiate SSL library
	SSL_load_error_strings();
	SSL_library_init();
    
    // start libevent thread
    CreateEventBase();
    eventThread_.Start(true);

    // initialize DnsResolver
    dns::Resolver::Init();
    
    // initialize srtp library
    fuze_srtp_init();
    
#ifndef WIN32 // avoid thread hanging as windows DLL kills all threads
    if (atexit(fuze_transport_at_exit) != 0) {
        WLOG("Failed to set fuze_transport_at_exit [" <<
             strerror(errno) << "] errno: " << errno <<
             " - rely on ResourceMgr to release now");
    }
#endif
    
    for (int i = TransportBase::NONE; i < TransportBase::END; ++i) {
        baseID_[i] = INVALID_ID;
    }
    
    for (int i = TransportUser::FUZE_SIP; i < TransportUser::END_USER; ++i ) {
        userList_[i] = 0;
    }
    
    // add one threads by default
    AddWorkerThread(0);
}

TransportImpl::~TransportImpl()
{
    // stop timer first
    timerService_.Terminate();
    
    // get rid of threads
    threadQ_.clear();
    
    for (int i = TransportUser::FUZE_SIP;
         i < TransportUser::TRANSPORT_RSR_MGR; ++i ) {
        if (userList_[i] != 0) {
            MLOG("Deleting " << toStr(TransportUser::Type(i)));
            delete userList_[i];
        }
    }
    
    spServer_.reset();
    
    if (pEventBase_) {
        {
            MutexLock scoped(&lock_);
            for (set<int>::iterator i = baseSet_.begin();
                 i != baseSet_.end(); ++i) {
                int base_id = *i;
                RequestReset(Resource::BASE, base_id);
            }
        }
        
        eventActive_ = false;
        
        if (eventThread_.IsRunning()) {
            
            MLOG("EventBase thread is running - loopbreak");
            event_base_loopbreak(pEventBase_);
            
            // in case it is waiting state, signal it
            // as this won't hurt the libevent thread
            semaphore_.Post();
            
            eventThread_.Join();
            MLOG("EventBase thread join complete");
        }
        
        MLOG("Releasing EventBase");
        event_base_free(pEventBase_);
        pEventBase_ = 0;
    }
    
    if (spProxy_) {
        spProxy_.reset();
    }

    dns::Resolver::Terminate();
    
#if defined(WIN32)
    MLOG("WSACleanup");
	WSACleanup();
#endif
    
    // lastly delete resource mgr
    if (userList_[TransportUser::TRANSPORT_RSR_MGR]) {
        MLOG("Deleting ResourceMgr");
        delete userList_[TransportUser::TRANSPORT_RSR_MGR];
    }
}

bool TransportImpl::Initialized()
{
    return (pEventBase_ != 0);
}

void TransportImpl::AddWorkerThread(size_t workerId)
{
    MLOG(workerId);
    
    MutexLock scoped(&sLock_);
    
    std::ostringstream name;
    name << "Worker " << workerId;
    WorkerThread::Ptr sp(new WorkerThread(name.str().c_str()));
    sp->Start();
    threadQ_.push_back(sp);
}
    
void TransportImpl::EnableServerMode(Mode mode)
{
    bServerMode_ = true;
    
    if (mode == MODE_ONLY) {
        MLOG("Enabling Server mode only (not listening on 443)");
    }
    else {
        if (!spServer_) {
            spServer_.reset(new Server);
            if (spServer_->Initialize() == false) {
                ELOG("Failed to initialize Transport Server");
                exit(1);
            }
        }
        else {
            WLOG("Transport server already exists");
        }
    }
}

void TransportImpl::SetNumberOfThread(int numThreads)
{
    if (numThreads == -1) {
#ifndef WIN32
        // match the number of threads with cpu cores
        int numCores = (int)sysconf(_SC_NPROCESSORS_ONLN);
        
        MLOG("Number of CPU Core available: " << numCores);
        
        numThreads = numCores;
#else
        WLOG("NOT SUPPORTED FOR WINDOWS YET");
#endif
    }

    if (numThreads > 0) {
        for (size_t i = threadQ_.size(); i < (size_t)numThreads; ++i) {
            AddWorkerThread(i);
        }
    }
}
    
void TransportImpl::Run()
{
    CongestionInfo info; // declare here so that we don't need to create everytime
    
    while (eventActive_) {
        // we assume that we have created event base at this point
        if (pEventBase_) {
            DLOG("Starting event base loop");

            //  0 if successful,
            // -1 if an error occurred,
            //  1 if no events were registered
            //
            int result = event_base_dispatch(pEventBase_);
            
            MLOG("Finished event base loop: " << result);

            if (result == -1) {
                MutexLock scoped(&lock_);
                ELOG("backend error on libevent");
                event_base_free(pEventBase_);
                pEventBase_ = 0;
                CreateEventBase(); // try again
            }
            else if (result == 1) {
                // if libevent thread came out due to no more event
                // then we need to wait for our next Event to be added
                MLOG("Libevent thread waiting for events to be added");
                semaphore_.Wait();
            }
            
            {
                MutexLock scoped(&lock_);
                loopexit_ = false; // mark that libevent have exited
            }
            
            // event thread may be out due to reset or connect request
            ResetRequest reset_req;
            while (GetResetRequest(reset_req)) {
                HandleResetRequest(reset_req);
            }
            
            int tcp_id = INVALID_ID;
            while (GetRequestedTcpID(tcp_id)) {
                HandlePostConnect(tcp_id);
            }
            
            while (GetCongestionRequest(info)) {
                HandleCongestionRequest(info);
            }
        }
        else {
            // MQT-1612
            // For Windows, it is likely the firewall not allowing us to bind
            // 127.0.0.1 address.
            // https://www.wangafu.net/~nickm/libevent-2.0/doxygen/html/util_8h.html
            //
            ELOG("[Fatal] Failed to create EventBase");
            break;
        }
    }
}
    
void TransportImpl::CreateEventBase()
{
    // we only need one event base to use
    if (pEventBase_) {
        return;
    }
    
    // mark event as
    eventActive_ = true;
    
    // get version
    MLOG("libevent version: " << event_get_version());
    
    // get supported methods
    const char** pp_methods = event_get_supported_methods();
    for (int i = 0; pp_methods[i] != 0; ++i) {
        MLOG(pp_methods[i] << " supported");
    }
    
    event_set_log_callback(event_log_cb);
    
	// set edge-trigger option if possible
	for (int i = 0; i < 2; ++i) {
		event_config* p_config = event_config_new();

		if (i == 0) {
			event_config_require_features(p_config, EV_FEATURE_ET);		
			event_config_set_flag(p_config, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);
		}

		pEventBase_ = event_base_new_with_config(p_config);

		event_config_free(p_config);

		if (pEventBase_) {
			MLOG("eventbase '" << event_base_get_method(pEventBase_) << 
				 "' created with" << (i == 0 ? "" : "out") << 
				 " edge-trigger feature");
			break;
		}
	}

    // create the only event base structure
    if (pEventBase_) {
        // get features
        int feature = event_base_get_features(pEventBase_);
        
        if (feature & EV_FEATURE_ET) {
            MLOG("Edge-Triggered supported");
        }
        else if (feature & EV_FEATURE_O1) {
            MLOG("O(1) Event Notifiaction supported");
        }
        else if (feature & EV_FEATURE_FDS) {
            MLOG("All FD types supported");
        }

		// Priority setting
		if (event_base_priority_init(pEventBase_, PT_MAX_PRIORITY) == -1) {
		 	ELOG("Failed to set priority " << PT_MAX_PRIORITY);
		}    
    }
	else {
		ELOG("Failed to create event base");		
	}        
}

bool TransportImpl::IsUdpBlocked()
{
    return spProber_->IsUdpBlocked();
}

bool TransportImpl::IsAppServer()
{
    return bServerMode_;
}

Server::Ptr TransportImpl::GetServer()
{
    return spServer_;
}
    
TransportBase::Ptr TransportImpl::CreateBase(const char* pName)
{
    TransportBase::Ptr sp_base;
    
    if (TransportBaseImpl* p = ResourceMgr::GetInstance()->GetNewBase()) {
        
        sp_base.reset(p, TransportBaseEnded);
        
        // for easier logging analysis
        if (pName) {
            p->SetName(pName);
        }

        int baseID = p->ID();
        MutexLock scoped(&lock_);
        baseSet_.insert(baseID);
    }
    
    return sp_base;
}

void TransportImpl::HandleResetRequest(const ResetRequest& rReq)
{
    switch (rReq.type_)
    {
    case Resource::BASE:
        if (rReq.id_ != INVALID_ID) { // here id_ is base id
            MutexLock scoped(&lock_);
            set<int>::iterator iter = baseSet_.find(rReq.id_);
            if (iter != baseSet_.end()) {
                baseSet_.erase(iter);
                if (TransportBaseImpl* p_base =
                    ResourceMgr::GetInstance()->GetBase(rReq.id_)) {
                    p_base->Reset();
                }
            }
        }
        break;
    case Resource::CONNECTION:
        // if connection was reset already then we wouldn't find one again
        if (ConnectionImpl* p_con =
                ResourceMgr::GetInstance()->GetConnection(rReq.id_)) {
            
            int base_id = p_con->BaseID();
            
            // find to see if base is valid
            if (base_id != -1) {
                MutexLock scoped(&lock_);
                set<int>::iterator iter = baseSet_.find(base_id);
                if (iter != baseSet_.end()) {
                    // notify TransportBaseImpl to clean up
                    if (TransportBaseImpl* p_base =
                        ResourceMgr::GetInstance()->GetBase(base_id)) {
                        p_base->RemoveConnection(rReq.id_);
                    }
                    else {
                        ELOG("Base ID " << base_id << " is not active!");
                    }
                }
            }
            
            p_con->Reset();
        }
        break;
    case Resource::SERVERCORE:
        // ServerCore is internal object and we do not have danger
        // of interacting with application threads that
        // following steps are not necessary but stick to
        // what has been done for BASE and CONNECTION
        if (ServerCore* p =
                ResourceMgr::GetInstance()->GetServerCore(rReq.id_)) {
            p->Reset();
        }
        break;
    case Resource::TCP_TRANSCEIVER:
    case Resource::UDP_TRANSCEIVER:
    case Resource::TCP_LISTENER:
        if (Transceiver* p =
                ResourceMgr::GetInstance()->GetTransceiver(rReq.type_,
                                                           rReq.id_)) {
            p->Reset();
        }
        break;
    default:;
    }
    
    if (rReq.pResource_) {
        ResourceMgr::GetInstance()->Release(rReq.pResource_);
    }
}
    
void TransportImpl::RegisterTraceObserver(TransportTraceObserver* pObserver, bool bPrefix)
{
    dout().SetTraceObserver(pObserver, bPrefix);
}

void TransportImpl::DeregisterTraceObserver()
{
    dout().SetTraceObserver(0);
}

const char* TransportImpl::GetCertificateFingerprint()
{
    return DtlsCore::GetFingerPrint();
}
    
void TransportImpl::SetUdpProbe(const string& rAddr, uint16_t port)
{
    spProber_->StartUdpProbe(rAddr, port);
}
    
void TransportImpl::SetLogLevel(SeverityType eType)
{
    gDebugLevel = eType;
}

void TransportImpl::RegisterTransportUser(TransportUser* pUser,
                                          TransportUser::Type type)
{
    MLOG(toStr(type));
    userList_[type] = pUser;
}

void TransportImpl::RegisterAkamaiTransport(const string& rRemote,
                                            const string& rAkamai)
{
    MLOG(rRemote << " - " << rAkamai);
    MutexLock scoped(&mapLock_);
    akamaiMap_[rRemote] = rAkamai;
}

string TransportImpl::GetAkamaiMapping(const string &rRemote)
{
    MutexLock scoped(&mapLock_);
    
    map<string, string>::iterator it = akamaiMap_.find(rRemote);
    if (it != akamaiMap_.end()) {
        return it->second;
    }
    
    return "";
}

void TransportImpl::SetMappingInfo(const string& mapInfo)
{
    MutexLock scoped(&lock_);
    mapInfo_ = mapInfo;
}
    
string TransportImpl::GetMappingInfo()
{
    MutexLock scoped(&lock_);
    return mapInfo_;
}
    
bool TransportImpl::CreateEvent(event*&           rpEvent,
                                evutil_socket_t   sock,
                                short             what,
                                event_callback_fn cb,
                                void*             pArg,
                                uint32_t          timeOut)
{
    bool bResult = false;
    
    if (sock == INVALID_SOCKET) {
        ELOG("Invalid socket used");
        return false;
    }
    
    if (!pEventBase_) {
        ELOG("Event base is not created");
        return false;
    }
    
    // we expect caller to set what with EV_TIMEOUT if timeOut is not 0
    rpEvent = event_new(pEventBase_, sock, what, cb, pArg);
    
    if (rpEvent) {
        
        timeval time_out = {0,0};
        
        if (timeOut > 0) {
            time_out.tv_sec  = timeOut / 1000;
            time_out.tv_usec = (timeOut % 1000) * 1000;
        }
        
        if (event_add(rpEvent, (timeOut ? &time_out : 0)) == 0) {
            DLOG("New " << (what & EV_WRITE ? "WRITE" : "") <<
                 (what & EV_READ ? "READ" : "") <<
                 " event is added for socket " << sock);
            if (semaphore_.GetCount() < 0) {
                MLOG("Event thread started");
                semaphore_.Post();
            }
            bResult = true;
        }
        else {
            ELOG("Failed to register event for socket " << sock);
            event_free(rpEvent);
            rpEvent = 0;
        }
    }
    else {
        ELOG("Failed to create event for socket " << sock);
    }
    
    return bResult;
}

void TransportImpl::RequestReset(Resource::Type eType, int ID, Resource* p)
{
    if (!eventActive_) {
        return;
    }

    ResetRequest reset_req;
    
    reset_req.type_      = eType;
    reset_req.id_        = ID;
    reset_req.pResource_ = p;
    
    {
        MutexLock scoped(&lock_);
        resetQ_.push(reset_req);

        PrintQSize();
        
        if (semaphore_.GetCount() < 0) {
            semaphore_.Post();
        }
        
        // for at most once triggering loopexit
        if (!loopexit_ && pEventBase_) {
            timeval delay;
            delay.tv_sec  = 0;
            delay.tv_usec = 10 * 1000; // after 10 ms of delay
            event_base_loopexit(pEventBase_, &delay);
            loopexit_ = true;
        }
    }
}

bool TransportImpl::GetResetRequest(ResetRequest& rResetReq)
{
    bool bResult = false;
    
    MutexLock scoped(&lock_);
    
    if (resetQ_.empty() == false) {
        rResetReq = resetQ_.front();
        resetQ_.pop();
        bResult = true;
    }
    
    return bResult;
}

void TransportImpl::RequestPostConnect(int tcpID)
{
    if (!eventActive_) {
        return;
    }
    
    {
        MutexLock scoped(&lock_);
        proxyQ_.push(tcpID);

        PrintQSize();
        
        if (semaphore_.GetCount() < 0) {
            semaphore_.Post();
        }
        
        // for at most once triggering loopexit
        if (!loopexit_ && pEventBase_) {
            if (event_base_loopexit(pEventBase_, 0) == -1) {
                ELOG("failed to event_base_loopexit");
            }
            loopexit_ = true;
        }
    }
}
    
bool TransportImpl::GetRequestedTcpID(int& rTcpID)
{
    bool bResult = false;
    
    MutexLock scoped(&lock_);
    
    if (proxyQ_.empty() == false) {
        rTcpID = proxyQ_.front();
        proxyQ_.pop();
        bResult = true;
    }
    
    return bResult;
}

void TransportImpl::HandlePostConnect(int tcpID)
{
    ResourceMgr* p_rm = ResourceMgr::GetInstance();
    
    if (Transceiver* p =
            p_rm->GetTransceiver(Resource::TCP_TRANSCEIVER, tcpID)) {
        if (TcpTransceiver* p_tcp = dynamic_cast<TcpTransceiver*>(p)) {
            p_tcp->StartAfterProxyConnect();
        }
    }
    else {
        ELOG("Failed to get TcpTransceiver with ID " << tcpID)
    }
}
    
void TransportImpl::EnableProxyConnector(bool enabled)
{
    if (enabled) {
        if (!spProxy_) {
            spProxy_.reset(new ProxyConnector);
        }
    }
    else {
        if (spProxy_) {
            spProxy_.reset();
        }
    }
}
    
ProxyConnector::Ptr TransportImpl::GetProxyConnector()
{
    return spProxy_;
}

TimerService& TransportImpl::GetTimerService()
{
    return timerService_;
}

void TransportImpl::PrintQSize()
{
    MLOG("resetQ_ size: " << resetQ_.size() <<
         " proxyQ_ size: " << proxyQ_.size() <<
         " congestQ_ size: " << congestQ_.size());
}
    
void TransportImpl::SetCongestionBaseID(TransportBase::Type eType, int baseID)
{
    MLOG(toStr(eType) << " ID:" << baseID);
 
    if (TransportBase::NONE < eType && eType < TransportBase::END) {
        baseID_[eType] = baseID;
    }
}
    
void TransportImpl::RequestCongestion(const CongestionInfo& rInfo)
{
    if (!eventActive_) {
        return;
    }
    
    {
        MutexLock scoped(&lock_);
        congestQ_.push(rInfo);
 
        PrintQSize();
        
        if (semaphore_.GetCount() < 0) {
            semaphore_.Post();
        }
        
        // for at most once triggering loopexit
        if (!loopexit_ && pEventBase_) {
            if (event_base_loopexit(pEventBase_, 0) == -1) {
                ELOG("failed to event_base_loopexit");
            }
            loopexit_ = true;
        }
    }
}
    
bool TransportImpl::GetCongestionRequest(CongestionInfo &rInfo)
{
    bool bResult = false;
    
    MutexLock scoped(&lock_);
    
    if (congestQ_.empty() == false) {
        rInfo = congestQ_.front();
        congestQ_.pop();
        bResult = true;
    }
    
    return bResult;
}

void TransportImpl::NotifyCongestion(TransportBase::Type eType, CongestionInfo &rInfo)
{
    int base_id = baseID_[eType];
    
    if (base_id != INVALID_ID) {
        // check if we have it in baseSet_
        if (baseSet_.find(base_id) == baseSet_.end()) {
            ELOG(toStr(eType) << "(" << base_id << ") is not active base!");
            return;
        }
        
        if (TransportBaseImpl* p = ResourceMgr::GetInstance()->GetBase(base_id)) {
            if (p->GetBaseType() == eType) {
                p->OnCongestion(rInfo);
            }
        }
    }
}
    
void TransportImpl::HandleCongestionRequest(CongestionInfo& rInfo)
{
    switch (GetSrcBaseType(rInfo))
    {
    case TransportBase::AUDIO:
        // notify video & screen share
        NotifyCongestion(TransportBase::VIDEO, rInfo);
        NotifyCongestion(TransportBase::SCREEN_SHARE, rInfo);
        break;
    case TransportBase::SCREEN_SHARE:
        // notify video
        NotifyCongestion(TransportBase::VIDEO, rInfo);
        break;
    default:;
    }
}

void TransportImpl::ReserveUdpPort(uint16_t port, int sock, uint32_t holdTime)
{
    PortReserve::Ptr sp_port(new PortReserve);
    sp_port->sock_    = sock;
    sp_port->timerID_ = StartTimer(sp_port, holdTime, port);
    
    MLOG("Port " << port << " reserved (s:" << sock << ") for " << holdTime << " ms");
    
    MutexLock scoped(&portLock_);
    mapPort_[port] = sp_port;
}

PortReserve::Ptr TransportImpl::GetReservedPort(uint16_t port)
{
    PortReserve::Ptr sp_port;
    
    MutexLock scoped(&portLock_);
    PortMap::iterator it = mapPort_.find(port);
    if (it != mapPort_.end()) {
        sp_port = it->second;
        mapPort_.erase(it);
        MLOG("Found reserved port " << port << " (s:" <<
             sp_port->sock_ << ", map size " << mapPort_.size() << ")");
    }
    
    return sp_port;
}

void PortReserve::OnTimer(int32_t AppData)
{
    // expired, remove the reservation
    MLOG("Reservation expired on port " << AppData);
    
    // remove it by getting it
    if (PortReserve::Ptr sp_rsv
            = TransportImpl::GetInstance()->GetReservedPort(AppData)) {
        MLOG("Closing port " << AppData << " (s:" << sp_rsv->sock_ << ")");
        evutil_closesocket(sp_rsv->sock_);
    }
}

void TransportImpl::SetDnsCache(const string& rDomain, Record::Type type, Record::List& rList)
{
    for (auto& it : rList) {
        it->expire_ = GetTimeMs() + (it->ttl_ * 1000);
    }
    
    if (!rList.empty()) {
        if (type == Record::A) {
            for (auto& a : rList) {
                if (A::Ptr sp = fuze_dynamic_pointer_cast<A>(a))
                    _MLOG_("[A] " << sp->hostName_ << " ttl " << sp->ttl_);
            }
        }
        else if (type == Record::SRV) {
            for (auto& srv : rList) {
                if (SRV::Ptr sp = fuze_dynamic_pointer_cast<SRV>(srv))
                    _MLOG_("[SRV] " << sp->name_ << ":" << sp->port_ <<
                           " ttl " << sp->ttl_ << " priority: " <<
                           sp->priority_ << " weight: " << sp->weight_);
            }
        }
        else if (type == Record::NAPTR) {
            for (auto& naptr : rList) {
                if (NAPTR::Ptr sp = fuze_dynamic_pointer_cast<NAPTR>(naptr)) {
                    _MLOG_("[NAPTR] " << sp->replacement_ << " ttl " <<
                           sp->ttl_ << " " << sp->flag_ << " " <<
                           sp->services_ << " order: " << sp->order_ <<
                           ", pref: " << sp->pref_ << " " << sp->regexp_);
                }
            }
        }
        
        MutexLock scoped(&dnsLock_);
        dnsCache_[type][rDomain] = rList;
    }
}
    
Record::List TransportImpl::GetDnsCache(const string& rDomain, Record::Type type)
{
    Record::List rec_list;

    MutexLock scoped(&dnsLock_);
    
    DnsRecordMap::iterator it = dnsCache_[type].find(rDomain);
    if (it != dnsCache_[type].end()) {
        if (!it->second.empty()) {
            Record::Ptr sp = *(it->second.begin());
            // check if this is expired
            if (GetTimeMs() > sp->expire_) {
                MLOG(rDomain << " (" << toStr(type) << ") expired");
                dnsCache_[type].erase(it);
            }
            else {
                DLOG(rDomain);
                rec_list = it->second;
            }
        }
    }

    return rec_list;
}

void TransportImpl::MarkDnsCacheBad(const string& rIPString)
{
    MutexLock scoped(&dnsLock_);
    
    DnsRecordMap::iterator it = dnsCache_[Record::A].begin();
    for (; it != dnsCache_[Record::A].end(); ++it) {
        for (auto& rec : it->second) {
            if (A::Ptr sp_a = fuze_dynamic_pointer_cast<A>(rec)) {
                if (rIPString == sp_a->hostName_) {
                    int ttl = 0;
                    int64_t curr_time = GetTimeMs();
                    if (curr_time < sp_a->expire_) {
                        ttl = int(sp_a->expire_ - curr_time);
                    }
                    
                    MLOG("Marking " << it->first << ":" <<
                         sp_a->hostName_ << " as bad A Record (ttl: " <<
                         ttl/1000 << " left)");
                    
                    sp_a->hostName_.clear();
                }
            }
        }
    }
}

void TransportImpl::ClearDnsCache()
{
    MLOG("");
    
    MutexLock scoped(&dnsLock_);

    dnsCache_[Record::A].clear();
    dnsCache_[Record::SRV].clear();
    dnsCache_[Record::NAPTR].clear();
}

WorkerThread::Ptr TransportImpl::GetWorker(fuze::ConnectionImpl* pConn)
{
    WorkerThread::Ptr sp;
    
    if (pConn->IsPayloadType(Connection::AUDIO)) {
        sp = threadQ_[0];
    }
    else if (pConn->IsPayloadType(Connection::VIDEO)) {
        sp = threadQ_[0];
    }
    else if (pConn->IsPayloadType(Connection::SS)) {
        if (threadQ_.size() > 1) {
            sp = threadQ_[1];
        }
        else {
            sp = threadQ_[0];
        }
    }
    else {
        sp = threadQ_[qIndex_++];
        
        if (qIndex_ == threadQ_.size()) {
            qIndex_ = 0;
        }
    }
    
    return sp;
}
    
WorkerThread::WorkerThread(const char* pName)
    : bActive_(false)
    , bExited_(false)
    , thread_(this, pName)
{
}

WorkerThread::~WorkerThread()
{
    End();
}

void WorkerThread::Start()
{
    if (!bActive_) {
        MLOG(thread_.Name());
        
        bool result = false;
        int  count  = 20; // try 2 seconds
        
        while (result == false && --count > 0) {
            result = thread_.Start();
            if (!result) {
                ELOG("Failed to create thread - try count: " << count);
                Thread::SleepInMs(100);
            }
        }
        
        bActive_ = result;
    }
}

void WorkerThread::End()
{
    if (bActive_) {
        bActive_ = false;
        
        MLOG("Stopping thread worker [" << thread_.Name() << "]");
        sem_.Post();
        
        int cnt = 20;
        while (!bExited_ && --cnt >= 0) {
            Thread::SleepInMs(100);
        }
        
        if (cnt < 0) {
            ELOG("Failed to stop thread worker [" << thread_.Name() << "]");
        }
        else {
            MLOG("worker thread [" << thread_.Name() << "] exited");
        }
    }
}

ThreadID WorkerThread::ID()
{
    return thread_.GetThreadID();
}

const char* WorkerThread::Name()
{
    return thread_.Name();
}
    
void WorkerThread::Run()
{
    ThreadID thrd_id = Thread::ID();
    
    while (bActive_) {
        if (ConnectionImpl* p = GetWork()) {
            // check if this is active and same thread is owning it
            if (p->IsActive()) {
                if (p->ServiceQueue(thrd_id) == false) {
                    WLOG("Connection rejected worker " << thread_.Name());
                }
            }
            else {
                WLOG("Inactive connection " << p->ID() << " detected");
            }
        }
        else {
            sem_.Wait();
        }
    }

    bExited_ = true;
}

void WorkerThread::SetWork(fuze::ConnectionImpl *pConn)
{
    {
        MutexLock scoped(&qLock_);
        
        queue_.push(pConn);
        
        size_t q_size = queue_.size();
        if (q_size > 10000) {
            WLOG(thread_.Name() << "'s q size: " << q_size << " clearing..");
            queue<ConnectionImpl*> empty_q;
            swap(queue_, empty_q);
        }
        else if ((q_size % 100) == 0) {
            MLOG(thread_.Name() << "'s q size: " << q_size);
        }
    }
    
    if (sem_.GetCount() < 0) {
        sem_.Post();
    }
}
    
ConnectionImpl* WorkerThread::GetWork()
{
    ConnectionImpl* p_conn = 0;

    MutexLock scoped(&qLock_);
    
    if (!queue_.empty()) {
        p_conn = queue_.front();
        queue_.pop();
    }
    
    return p_conn;
}
    
} // namespace fuze
