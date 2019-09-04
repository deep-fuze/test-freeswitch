//
//  Server.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/10/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Server.h>
#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <TcpTransceiver.h>
#include <ResourceMgr.h>

#include <Log.h>

#ifdef __linux__
#include <string.h>
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "FwSrv[s" << socket_ << ":map" << bindingMap_.size() << ":set"<< coreSet_.size() << "] " << __FUZE_FUNC__ << ": " << B)

#ifndef WIN32

#include <errno.h>
#include <string.h>

/* True iff e is an error that means a accept can be retried. */
#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)  \
        ((e) == EINTR || (e) == EAGAIN || (e) == ECONNABORTED)
/* True iff e is an error that means a read/write operation can be retried. */
#define EVUTIL_ERR_RW_RETRIABLE(e)		\
        ((e) == EINTR || (e) == EAGAIN)

#else // end posix

#define EVUTIL_ERR_ACCEPT_RETRIABLE(e) EVUTIL_ERR_RW_RETRIABLE(e)
#define EVUTIL_ERR_RW_RETRIABLE(e)      \
        ((e) == WSAEWOULDBLOCK ||		\
        (e) == WSAEINTR)

#endif

namespace fuze {
    
void server_callback(evutil_socket_t socket, short what, void* pArg)
{
    // Accept the connection
    if (Server* p = reinterpret_cast<Server*>(pArg)) {
        p->OnListenEvent(socket, what);
    }
}
    
Server::Server()
    : socket_(INVALID_SOCKET)
    , pReadEvent_(0)
    , lastCleanTime_(GetTimeMs())
{
}

Server::~Server()
{
    if (pReadEvent_) {
        event_free(pReadEvent_);
    }
    pReadEvent_ = 0;
    
    if (socket_ != INVALID_SOCKET) {
        evutil_closesocket(socket_);
    }
    socket_ = INVALID_SOCKET;
}

bool Server::Initialize()
{
    bool bResult = false;

    if (socket_ != INVALID_SOCKET) {
        ELOG("Socket is already initialized");
        return false;
    }
    
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        ELOG("Failed to create socket")
        return false;
    }
    
    evutil_make_socket_nonblocking(socket_);
    evutil_make_listen_socket_reuseable(socket_);
        
    // we bind the address and listen at this address
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (::bind(socket_, (sockaddr*)&addr, sizeof(addr)) != -1) {
        MLOG("bind() on socket " << socket_ << " - port " << PORT);
        if (listen(socket_, SOMAXCONN) != -1) {
            TransportImpl* p = TransportImpl::GetInstance();
            bResult = p->CreateEvent(pReadEvent_,
                                     socket_,
                                     EV_READ|EV_PERSIST,
                                     server_callback,
                                     this);
            if (bResult) {
                MLOG("listen() on socket " << socket_);
            }
        }
        else {
            int e = evutil_socket_geterror(socket_);
            ELOG("Error listen on socket " << socket_ << " - " <<
                 evutil_socket_error_to_string(e));
        }
    }
    else {
        ELOG("Failed to bind on port " << PORT);
    }
    
    if (bResult == false) {
        if (socket_ != INVALID_SOCKET) {
            evutil_closesocket(socket_);
        }
        socket_ = INVALID_SOCKET;
    }
    else {
        // create media bridge now
        spBridge_.reset(new MediaBridge);
    }
    
    return bResult;
}
    
void Server::OnListenEvent(evutil_socket_t sock, short what)
{
    if (socket_ != sock) {
        ELOG("Socket doesn't match! " << socket_ << ":" << sock);
        return; // is this enough? something has gone wrong bad..
    }
    
    if (what & EV_READ) {
        
        sockaddr_storage ss;
        ev_socklen_t     len = sizeof(ss);
        evutil_socket_t  new_fd = accept(socket_, (sockaddr*)&ss, &len);
        
        if (new_fd != INVALID_SOCKET) {
            MLOG("new incoming client - s" << new_fd);
            evutil_make_socket_nonblocking(new_fd);
#ifdef SO_NOSIGPIPE
            int on = 1;
            if (setsockopt(new_fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on,
                           sizeof(on)) < 0) {
                ELOG("Failed to set SO_NOSIGPIPE errno " << errno);
            }
#endif
            CleanupCoreSet();
            
            if (ServerCore* p = ResourceMgr::GetInstance()->GetNewServerCore()) {
                coreSet_.insert(p->ID());
                p->SetSocket(new_fd);
                p->SetStartTime(); // mark the start time to guard against network attack
            }
            else {
                ELOG("Failed to create addtional clients");
                evutil_closesocket(new_fd);
            }
        }
        else {
            int e = evutil_socket_geterror(socket_);
            if (EVUTIL_ERR_ACCEPT_RETRIABLE(e)) {
                MLOG("Retry accept() due to " << evutil_socket_error_to_string(e));
            }
            else {
                ELOG(evutil_socket_error_to_string(e));
            }
        }
    }
}

void Server::CleanupCoreSet()
{
    int64_t now = GetTimeMs();
    
    if ((now-lastCleanTime_) < CLEANUP_PERIOD) {
        return;
    }
    
    set<int> expired_set;
    
    for (set<int>::iterator i = coreSet_.begin(); i != coreSet_.end(); ++i) {
        if (ServerCore* p = ResourceMgr::GetInstance()->GetServerCore(*i)) {
            int64_t diff = now - p->GetStartTime();
            if (diff > MAX_CORE_IDLE_MS) {
                MLOG("ServerCore [co" << *i << "] idle for " << diff << " ms" );
                expired_set.insert(*i);
            }
        }
    }
    
    for (set<int>::iterator i = expired_set.begin(); i != expired_set.end(); ++i) {
        RemoveServerCore(*i);
    }
}
    
void Server::SetConnectionBinding(int connID)
{
    if (ConnectionImpl* p_con =
            ResourceMgr::GetInstance()->GetConnection(connID)) {
 
        ConnectionType type;
        string         IP;
        uint16_t       port;
        
        if (p_con->GetConnectedType(type) && p_con->GetLocalAddress(IP, port)) {
            BindingKey key = (type << 16) | port;
            // register this connection to be connected by other means
            // such as TCP/TLS/HTTP/HTTPS
            MLOG("Binding created for " << toStr(type) << " [c" << connID <<
                 "] (" << IP << ":" << port << ")");
            
            BindingInfo info;
            info.type_   = type;
            info.ipStr_  = IP;
            info.port_   = port;
            info.connID_ = connID;
            
            MutexLock scoped(&lock_);
            bindingMap_[key] = info;
        }
        else {
            ELOG("invalid data to bind connection [c" << connID << "]");
        }
    }
}

void Server::RemoveConnectionBinding(int connID)
{
    if (ConnectionImpl* p_con =
            ResourceMgr::GetInstance()->GetConnection(connID)) {

        ConnectionType type;
        string         IP;
        uint16_t       port;

        if (p_con->GetConnectedType(type) && p_con->GetLocalAddress(IP, port)) {
            BindingKey key = (type << 16) | port;
            MutexLock scoped(&lock_);
            BindingMap::iterator it = bindingMap_.find(key);
            if (it != bindingMap_.end()) {
                MLOG("Found matching binding for " << toStr(type) <<
                     " (" << IP << ":" << port << ")");
                bindingMap_.erase(it);
            }
            else {
                ELOG("Connection binding not found for " << toStr(type) <<
                     " (" << IP << ":" << port << ")");
            }
        }
        else {
            ELOG("invalid data to bind connection [c" << connID << "]");
        }
    }
    else {
        ELOG("Connection is not active");
    }
}
    
void Server::RemoveServerCore(int coreID)
{
    set<int>::iterator it = coreSet_.find(coreID);
    
    if (it != coreSet_.end()) {
        coreSet_.erase(it); // remove from our active set
        
        // now request the libevent thread to reset the client
        if (ServerCore* p = ResourceMgr::GetInstance()->GetServerCore(coreID)) {
            TransportImpl::GetInstance()->RequestReset(Resource::SERVERCORE, coreID, p);
            MLOG("ServerCore [co" << coreID << "] requested to be removed");
        }
        else {
            ELOG("ServerCore [co" << coreID << "] is not active");
        }
    }
    else {
        WLOG("ServerCore [co" << coreID << "] is not in active set");
    }
}

bool Server::GetBindingInfo(BindingInfo& rInfo, Mapping& reqMap)
{
    bool bResult = false;
    
    BindingKey key = (reqMap.ConnType() << 16) | reqMap.Port();

    // first look up in portMap_ to retrieve connection ID
    {
        MutexLock scoped(&lock_);
        
        BindingMap::iterator it = bindingMap_.find(key);
        if (it != bindingMap_.end()) {
            rInfo = it->second;
        }
    }
    
    if (ResourceMgr::GetInstance()->GetConnection(rInfo.connID_)) {
        MLOG("Mapping found for " << toStr(reqMap.ConnType()) <<
             " [c" << rInfo.connID_ << "] " <<
             rInfo.ipStr_ << ":" << reqMap.Port());
        bResult = true;
    }
    else {
        ELOG("Connection [c" << rInfo.connID_ << "] is not active");
    }
    
    return bResult;
}    
    
} // namespace fuze
