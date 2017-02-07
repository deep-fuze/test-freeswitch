//
//  TcpListener.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/25/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <TcpListener.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_TCP, "TcpListen[c" << connID_ << ":s" << socket_ << ":r" << ID() << "] " << __FUZE_FUNC__ << ": " << B)

#ifndef WIN32

#include <errno.h>
#include <string.h>

/* True iff e is an error that means a accept can be retried. */
#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)			\
((e) == EINTR || (e) == EAGAIN || (e) == ECONNABORTED)

#else // not WIN32

#define EVUTIL_ERR_RW_RETRIABLE(e)          \
        ((e) == WSAEWOULDBLOCK ||           \
        (e) == WSAEINTR)

#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)		\
        EVUTIL_ERR_RW_RETRIABLE(e)

#endif


namespace fuze {

static void listener_callback(evutil_socket_t socket, short what, void *pArg)
{
    DEBUG_OUT(LEVEL_DEBUG, AREA_COM, "listener socket " << socket << " has incoming ");
    // accept the connection
    TcpListener* p = reinterpret_cast<TcpListener*>(pArg);
    
    try {
        if (p) {
            p->HandleAccept(socket, what);
        }
    }
    catch (const std::exception& ex) {
        DEBUG_OUT(LEVEL_ERROR, AREA_COM, "TcpListener: exception - " <<
                  ex.what());
    }
    catch (...) {
        DEBUG_OUT(LEVEL_ERROR, AREA_COM, "TcpListener: unknown exception");
    }
}
    
TcpListener::TcpListener(int transID)
    : Transceiver(transID)
    , connID_(INVALID_ID)
    , pConn_(0)
    , socket_(INVALID_SOCKET)
    , pReadEvent_(0)
{
}

void TcpListener::Reset()
{
    if (IsActive() == true) {
        MLOG("ACTIVE -> ZOMBIE");
        SetZombie();
        connID_ = INVALID_ID;
        pConn_  = 0;
        
        // To deallocate an event, call event_free(). It is safe to call
        // event_free() on an event that is pending or active: doing so makes
        // the event non-pending and inactive before deallocating it.
        if (pReadEvent_) {
            event_free(pReadEvent_);
        }
        pReadEvent_ = 0;
        
        if (socket_ != INVALID_SOCKET) {
            evutil_closesocket(socket_);
        }
        socket_ = INVALID_SOCKET;
    }
}

ConnectionType TcpListener::ConnType()
{
    return CT_TCP_LISTENER;
}
    
void TcpListener::SetConnectionID(int connID)
{
    if (connID != INVALID_ID) {
        connID_ = connID;
        pConn_  = ResourceMgr::GetInstance()->GetConnection(connID);
    }
}

bool TcpListener::Start()
{
    if (connID_ == INVALID_ID || !pConn_) {
        ELOG("Connection is not linked");
        return false;
    }
    
    // we bind the address and listen at this address
    Address local = pConn_->GetLocalAddress();
    
    socket_ = socket(local.IPType(), SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        ELOG("Failed to create socket")
        return false;
    }
    
    bool bResult = false;
    
    evutil_make_socket_nonblocking(socket_);
    evutil_make_listen_socket_reuseable(socket_);
    
    if (::bind(socket_, local.SockAddr(), local.SockAddrLen()) != -1) {
        MLOG("bind() on socket " << socket_ << " - " << local);
        if (listen(socket_, SOMAXCONN) != -1) {
            TransportImpl* p = TransportImpl::GetInstance();
            bResult = p->CreateEvent(pReadEvent_,
                                     socket_,
                                     EV_READ|EV_PERSIST,
                                     listener_callback,
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
        ELOG("Failed to bind on " << local);
    }
    
    if (bResult == false) {
        if (socket_ != INVALID_SOCKET) {
            evutil_closesocket(socket_);
        }
        socket_ = INVALID_SOCKET;
    }
    
    return bResult;    
}

void TcpListener::HandleAccept(evutil_socket_t sock, short what)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (socket_ != sock) {
        ELOG("Socket doesn't match! " << socket_ << ":" << sock);
        return;
    }
    
    if (!pConn_) {
        ELOG("Failed to get active connection");
        event_del(pReadEvent_);
        TransportImpl::GetInstance()->RequestReset(Resource::CONNECTION, connID_);
        return;
    }
    
    if (what & EV_READ) {
        
        sockaddr_storage ss;
        ev_socklen_t     len = sizeof(ss);
        evutil_socket_t  new_fd = accept(socket_, (sockaddr*)&ss, &len);
        
        if (new_fd != INVALID_SOCKET) {
            MLOG("new client connection [s" << new_fd << "] accepted");
            evutil_make_socket_nonblocking(new_fd);

            int base_id = pConn_->BaseID();
            if (TransportBaseImpl* p =
                    ResourceMgr::GetInstance()->GetBase(base_id)) {
                p->AddNewConnection(new_fd);
            }
            else {
                ELOG("Failed to get base ID" << base_id);
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
                pConn_->OnEvent(ET_FAILED, "Accept failure");
            }
        }
    }
    else {
        ELOG("Ignoring Unknown event " << what);
    }
}

bool TcpListener::Send(Buffer::Ptr spBuffer)
{
    ELOG("Sending is not allowed");
    return false;
}

bool TcpListener::Send(const uint8_t* buf, size_t size)
{
    ELOG("Sending is not allowed");
    return false;
}
    
} // namespace fuze
