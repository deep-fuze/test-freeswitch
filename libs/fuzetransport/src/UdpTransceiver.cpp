//
//  UdpTransceiver.cpp
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <UdpTransceiver.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <string.h>
#include <Log.h>

#ifdef __linux__
#include <string.h> // memset
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_UDP, "Udp[c" << connID_ << ":s" << socket_ << ":" << pName_ << "] " << __FUZE_FUNC__ << ": " << B)

#ifndef WIN32
#include <errno.h>
#include <string.h>
/* True iff e is an error that means a read/write operation can be retried. */
#define EVUTIL_ERR_RW_RETRIABLE(e) \
        ((e) == EINTR || (e) == EAGAIN)
#define EVUTIL_ERR_CONNECT_REFUSED(e) \
        ((e) == ECONNREFUSED)
#define EVUTIL_ERR_CONNECT_RESET(e) \
        ((e) == ECONNRESET)
#else

#include <ws2ipdef.h>
#include <WinSock2.h>

#define EVUTIL_ERR_RW_RETRIABLE(e) \
        ((e) == WSAEWOULDBLOCK || (e) == WSAEINTR)
#define EVUTIL_ERR_CONNECT_REFUSED(e) \
        ((e) == WSAECONNREFUSED)
#define EVUTIL_ERR_CONNECT_RESET(e) \
        ((e) == WSAECONNRESET)
#endif

namespace fuze {

UdpTransceiver::UdpTransceiver(int transID)
    : Transceiver(transID)
    , connID_(INVALID_ID)
    , pConn_(0)
    , socket_(INVALID_SOCKET)
    , pReadEvent_(0)
    , pWriteEvent_(0)
    , connectedUdp_(false)
    , remotePort_(0)
    , bConnected_(false)
    , writeAdded_(false)
    , recvBufSize_(2000)
    , recvCnt_(0)
    , checkTime_(0)
    , lastRecvCnt_(0)
    , remoteChangeCnt_(0)
    , reservedPort_(false)
{
    memset(pName_, 0, 16);
}

void UdpTransceiver::Reset()
{
    // Workaround the thread race condition between app and libevent
    // until we implement UDP sendQ_
    MutexLock scoped(&qlock_);
    
    if (IsActive()) {
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

        if (pWriteEvent_) {
            event_free(pWriteEvent_);
        }
        pWriteEvent_ = 0;
        
        if (socket_ != INVALID_SOCKET) {
            
            if (TransportImpl* p = TransportImpl::GetInstance()) {
                if (flowID_ != 0) {
                    p->UnsetQoSTag(socket_, flowID_);
                    flowID_ = 0;
                }
            }

            if (!reservedPort_) {
                evutil_closesocket(socket_);
            }
            else {
                sockaddr_storage local;
                ev_socklen_t     len = sizeof(sockaddr_storage);

                if (getsockname(socket_, (sockaddr*)&local, &len) == 0) {
                    Address addr(local);
                    uint16_t local_port = addr.Port();
                    MLOG("socket interrogation result: " << addr.IPString() <<
                         ":" << local_port);
                    
                    if (evutil_closesocket(socket_) == 0) {
                        MLOG("socket is closed - reserving the port again"
                             " so that it is not used.");
                        const int MAX_TIME = 3 * 60 * 60 * 1000; // three hours
                        if (ReserveUdpPort(MAX_TIME, local_port) == false) {
                            ELOG("Failed to reserve UDP port:" << local_port);
                        }
                    }
                    else {
                        int e = evutil_socket_geterror(socket_);
                        ELOG("evutil_closesocket failed: " <<
                             evutil_socket_error_to_string(e) << ". errno=" << e);
                    }
                }
                else {
                    int e = evutil_socket_geterror(socket_);
                    ELOG("getsockname failed: " <<
                         evutil_socket_error_to_string(e) << ". errno=" << e);
                }
            }
        }
        
        socket_ = INVALID_SOCKET;

        connectedUdp_    = false;
        remotePort_      = 0;
        bConnected_      = false;
        recvCnt_         = 0;
        checkTime_       = 0;
        lastRecvCnt_     = 0;
        remoteChangeCnt_ = 0;
        writeAdded_      = false;
        reservedPort_    = false;
        
        queue<Buffer::Ptr> empty;
        swap(sendQ_, empty);
        
        lastNewRemoteAddr_.Clear();

        remoteIP_.erase();

        memset(pName_, 0, 16);
    }
}

ConnectionType UdpTransceiver::ConnType()
{
    return CT_UDP;
}

void UdpTransceiver::SetConnectionID(int connID)
{
    if (connID != INVALID_ID) {
        connID_ = connID;
        pConn_ = ResourceMgr::GetInstance()->GetConnection(connID);
        memcpy(pName_, pConn_->GetName(), 15);
        reservedPort_ = pConn_->UsePortReservation();
    }
}

bool UdpTransceiver::Start()
{
    if (connID_ == INVALID_ID || !pConn_) {
        ELOG("Connection is not linked");
        return false;
    }
    
    TransportImpl* p_tp = TransportImpl::GetInstance();
    
    //
    // if local address is not available but remote address is,
    // this means this is connected UDP we are creating. Otherwise,
    // we just need local address to start binding and listening for
    // any incoming packet.  SetRemoteAddress can happen any time later
    // for normal UDP mode.
    //
    Address addr = pConn_->GetLocalAddress();
    
    if (addr.Valid() == false) {
        addr = pConn_->GetRemoteAddress();
        if (addr.Valid()) {
            connectedUdp_ = true;
        }
        else {
            ELOG("No IP address available to start ");
            return false;
        }
    }
    
    bool bResult = false;
    
    if (!connectedUdp_) {
        if (PortReserve::Ptr sp_rsv = p_tp->GetReservedPort(addr.Port())) {
            MLOG("Found reserved port: " << addr.Port() <<
                 " (s:" << sp_rsv->sock_ << ")");
            socket_ = sp_rsv->sock_;
            StopTimer(sp_rsv, sp_rsv->timerID_);
            bResult = true;
        }
    }
    
    if (socket_ == INVALID_SOCKET) {
        socket_ = socket(addr.IPType(), SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET) {
            ELOG("Failed to create socket")
            return false;
        }
    }
    
    if (!connectedUdp_) {
        // if port was not reserved then we would not have port bound
        if (bResult == false) {
            if (::bind(socket_, addr.SockAddr(), addr.SockAddrLen()) == 0) {
                bResult = true;
            }
        }
    }
    else {
        if (::connect(socket_, addr.SockAddr(), addr.SockAddrLen()) == 0) {
            
            // if connected UDP is used then get local address
            // that is set by operating system
            sockaddr_storage local;
            ev_socklen_t     len = sizeof(sockaddr_storage);
            
            if (getsockname(socket_, (sockaddr*)&local, &len) == 0) {
                Address local_addr(local);
                MLOG("local address: " << local_addr);
                pConn_->SetLocalAddress(local_addr.IPString(),
                                        local_addr.Port());
            }
            else {
                ELOG("Error at getsockname()");
            }
            
            bResult = true;
        }
    }

    if (bResult) {
        DLOG("socket " << socket_ <<
             (connectedUdp_ ? " connected" : " bound") <<
             " to " << addr);
        
        evutil_make_socket_nonblocking(socket_);
        evutil_make_listen_socket_reuseable(socket_);
        
        p_tp->SetQoSTag(socket_, pConn_, flowID_);
        
        if (pConn_->IsPayloadType(Connection::SIP)) {
            MLOG("adjusting recv buf size to 30000");
            recvBufSize_ = 30000;
        }

        uint16_t timeout = 0;
        
        if (p_tp->IsAppServer() == false) {
            if (pConn_->IsFallback()) {
                if (pConn_->IsPayloadType(Connection::RTP)) {
                    timeout = RTP_TIMEOUT;
                }
                if (pConn_->IsPayloadType(Connection::RTCP)) {
                    timeout = RTCP_TIMEOUT;
                }
                
                if (timeout != 0 && p_tp->IsUdpBlocked()) {
                    timeout /= 5;
                    MLOG("UDP seems blocked - shorten timeout to " << timeout << " ms");
                    // if proxy is not set then try longer timeout
                    string proxy, credential;
                    proxy::Type type;
                    proxy::GetInfo(proxy, credential, type);
                    if (proxy.empty()) {
                        timeout *= 2;
                        MLOG("No proxy setup - extend timeout to " << timeout << " ms");
                    }
                }
            }
            else {
                MLOG("Disabling read timeout as fallback is disabled");
            }
        }
        
        bResult = CreateLibEvent(timeout);
    }
    else {
        int e = evutil_socket_geterror(socket_);
        ELOG("Failed to " << (connectedUdp_  ? "connect" : "bind") <<
             " to " << addr << " (" <<
             evutil_socket_error_to_string(e) << ") errno=" << e);
    }
    
    return bResult;
}

bool UdpTransceiver::CreateLibEvent(uint16_t timeout)
{
    bool bResult = false;

    if (pReadEvent_) {
        event_free(pReadEvent_);
        pReadEvent_ = 0;
    }
    
    if (TransportImpl* p = TransportImpl::GetInstance()) {
        
        short what = EV_READ|EV_PERSIST;
        
        // if this is client, then trigger timeout
        if (timeout > 0) {
            MLOG("Setting socket read timeout as " << timeout << "ms");
            what |= EV_TIMEOUT;
        }
        
        bResult = p->CreateEvent(pReadEvent_, socket_, what,
                                 OnLibEvent, this, timeout);
    }
    
    return bResult;
}
    
void UdpTransceiver::OnLibEvent(evutil_socket_t sock, short what, void* pArg)
{
    _DLOG_("socket " << sock << " has event " <<
           (what & EV_READ ? "READ" : "") <<
           (what & EV_WRITE ? "WRITE" : ""));
    
    if (UdpTransceiver* p = reinterpret_cast<UdpTransceiver*>(pArg)) {
        if (p->socket_ != sock) {
            return;
        }
        
        try {
            if (what & EV_READ) {
                p->OnReadEvent();
            }
            if (what & EV_WRITE) {
                p->OnWriteEvent();
            }
            if (what & EV_TIMEOUT) {
                p->OnTimeOutEvent();
            }
        }
        catch (const std::exception& ex) {
            _ELOG_("exception - " << ex.what());
        }
        catch (...) {
            _ELOG_("unknown exception");
        }
    }
}

bool UdpTransceiver::Send(Buffer::Ptr spBuffer)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    if ((socket_ == INVALID_SOCKET) || !pConn_) {
        return false;
    }
    
    MutexLock scoped(&qlock_);
    
    sendQ_.push(spBuffer);
    
    // trigger write operation if not done yet for first time
    if (!pWriteEvent_) {
        if (TransportImpl* p = TransportImpl::GetInstance()) {
            writeAdded_ = p->CreateEvent(pWriteEvent_,
                                         socket_,
                                         EV_WRITE|EV_PERSIST,
                                         OnLibEvent, this);
        }
    }
    else {
        if (!writeAdded_ && pWriteEvent_) {
            DLOG("Write event registered");
            event_add(pWriteEvent_, 0);
            writeAdded_ = true;
        }
    }
    
    return true;
}

bool UdpTransceiver::Send(const uint8_t* buf, size_t size)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }

    if ((socket_ == INVALID_SOCKET) || !pConn_) {
        return false;
    }

    SendPayload((char*)buf, size, pConn_->GetRemoteAddress());
    
    return true;
}

void UdpTransceiver::OnWriteEvent()
{
    while (true) {
        
        Buffer::Ptr sp_buf;
        
        {
            MutexLock scoped(&qlock_);
            if (sendQ_.empty()) {
                if (writeAdded_ && pWriteEvent_) {
                    event_del(pWriteEvent_);
                    writeAdded_ = false;
                }
                return;
            }
            else {
                sp_buf = sendQ_.front();
                sendQ_.pop();
            }
        }
        
        Address remote;
        
        if (!connectedUdp_) {
            // first set connection remote as default remote address
            if (pConn_->IsRemotePerBuffer()) {
                if (NetworkBuffer::Ptr sp_net =
                        fuze_dynamic_pointer_cast<NetworkBuffer>(sp_buf)) {
                    remote.SetIP(sp_net->remoteIP_.c_str());
                    remote.SetPort(sp_net->remotePort_);
                }
            }
            else {
                remote = pConn_->GetRemoteAddress();
            }
        }
        
        SendPayload((char*)sp_buf->getBuf(), sp_buf->size(), remote);
    }
}

void UdpTransceiver::SendPayload(char* pData, long dataLen, const Address& rRemote)
{
    if (!pData || !dataLen) {
        WLOG("0 bytes was requested to send - ignored");
        return;
    }

    if (pConn_->IsPayloadType(Connection::STUN)) {
        if (stun::IsStun(pData, dataLen)) {
            MLOG(toStr(stun::GetType(pData, dataLen)) << " " <<
                 toStr(stun::GetMethod(pData, dataLen)) <<
                 " (" << dataLen << "B)");
            stun::PrintStun(pData, dataLen);
        }
    }

    long sent = 0;

    if (connectedUdp_) {
        sent = send(socket_, pData, dataLen, 0);
    }
    else {
        sent = sendto(socket_, pData, dataLen, 0,
                      rRemote.SockAddr(), rRemote.SockAddrLen());
    }

    if (sent == dataLen) {
        pConn_->OnBytesSent((uint32_t)sent);
    }
    else if (sent > 0) {
        WLOG("Only sent " << sent << "/" << dataLen << "B");
    }
    else { // -1 returned
        static int s_last_error;
        static int s_counter;
        int error = evutil_socket_geterror(socket_);
        if (s_last_error != error) {
            s_counter = 0;
        }
        if (!(s_counter++ % 10)) {
            ELOG("Error: " << error << " (" <<
                 evutil_socket_error_to_string(error) << ") cnt: " <<
                 s_counter);
            s_last_error = error;
        }
    }
}
    
void UdpTransceiver::OnReadEvent()
{
//#define FALLBACK_TEST
#ifdef FALLBACK_TEST
    if (pConn_->IsPayloadType(Connection::RTP)) {
        static bool refused = false;
        if (refused == false) {
            pConn_->OnEvent(ET_REFUSED);
            refused = true;
        }
        return;
    }
#endif
    
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (connID_ == INVALID_ID || !pConn_) {
        ELOG("Failed to get active connection")
        return;
    }
    
    long udp_bytes = -1;
    
    do {
        sockaddr_storage saddr;
        
        NetworkBuffer::Ptr sp_packet = pConn_->GetBuffer(recvBufSize_);
        
		char*    p_buf = (char*)sp_packet->getBuf();
		uint32_t size  = sp_packet->size();

        if (connectedUdp_) {
            udp_bytes = recv(socket_, p_buf, size, 0);
        }
        else {
            ev_socklen_t slen = sizeof(sockaddr_storage);            
            udp_bytes = recvfrom(socket_, p_buf, size, 0,
                                 (sockaddr*)&saddr, &slen);
        }
        
        if (udp_bytes > 0) {
            
            pConn_->OnBytesRecv((uint32_t)udp_bytes);
            
            if (pConn_->IsPayloadType(Connection::STUN)) {
                if (stun::IsStun(p_buf, udp_bytes)) {
                    MLOG(toStr(stun::GetType(p_buf, udp_bytes)) << " " <<
                         toStr(stun::GetMethod(p_buf, udp_bytes)) <<
                         " (" << udp_bytes << "B)");
                    stun::PrintStun(p_buf, udp_bytes);
                }
            }
            
            if (!bConnected_) {
                // set active timer now
                if ((TransportImpl::GetInstance()->IsAppServer() == false) &&
                    TransportImpl::GetInstance()->IsUdpBlocked()) {

                    MLOG("Network seemed blocking UDP but it wasn't");
                    
                    uint16_t new_timeout = 0;
                    
                    if (pConn_->IsPayloadType(Connection::RTP)) {
                        new_timeout = RTP_TIMEOUT;
                    }
                    
                    if (pConn_->IsPayloadType(Connection::RTCP)) {
                        new_timeout = RTCP_TIMEOUT;
                    }

                    if (new_timeout > 0) {
                        MLOG("Resetting timer as " << new_timeout << " ms");
                        CreateLibEvent(new_timeout);
                    }
                }
                
                bConnected_ = true;
            }
            
            sp_packet->setSize((uint32_t)udp_bytes);
            
            Address recv_addr(saddr);
            
            // for connected UDP, application already knows the remote as it was
            // the requirement of doing connected udp
            if (pConn_->IsRemotePerBuffer()) {
                sp_packet->remoteIP_   = recv_addr.IPString();
                sp_packet->remotePort_ = recv_addr.Port();
            }
            else if (!connectedUdp_ && pConn_->IsValidRemote(recv_addr) == false) {
                if (!HandleRemoteChange(recv_addr)) {
                    return; // ignoring invalid remote address
                }
                
                sp_packet->remoteIP_   = remoteIP_;
                sp_packet->remotePort_ = remotePort_;
                sp_packet->changed_    = true;
            }
            
            // count the number of valid packet received
            recvCnt_++;
            
            pConn_->OnData(sp_packet);
        }
        else {
            int error = evutil_socket_geterror(socket_);
            if (EVUTIL_ERR_RW_RETRIABLE(error) == false) {
                ELOG("Error: " << error << " (" <<
                     evutil_socket_error_to_string(error) << ")");
                event_del(pReadEvent_);
                
                {
                    MutexLock scoped(&qlock_);
                    if (writeAdded_ && pWriteEvent_) {
                        event_del(pWriteEvent_);
                        writeAdded_ = false;
                    }
                }
                
                const char* p_reason = "Unknown";
                
                EventType type = ET_FAILED;
                if (EVUTIL_ERR_CONNECT_REFUSED(error)) {
                    type = ET_REFUSED;
                    p_reason = "Refused";
                }
                else if (EVUTIL_ERR_CONNECT_RESET(error)) {
                    p_reason = "ICMP Unreachable";
                }
                
                pConn_->OnEvent(type, p_reason);
            }
        }
    } while (udp_bytes > 0);
}

bool UdpTransceiver::HandleRemoteChange(const Address& rRecvAddr)
{
    // for client, we don't allow remote address change
    // for server, we allow change remote address change
    // only when following condition is met
    //   1) this is very first packet
    //   2) current stream stopped for at least 2 seconds
    //      and new stream is streaming more than 2 seconds
    // otherwise ignore packets with different source address
    
    // for client we shouldn't see this happening but
    // some wifi NAT device is doing weird forwarding
    Address remote = pConn_->GetRemoteAddress();
    
    if (TransportImpl::GetInstance()->IsAppServer() == false) {
        if ((++remoteChangeCnt_ % 100 == 1) ||
            (remoteChangeCnt_ <= 10)) {
            ELOG("Detected different remote address - " <<
                 rRecvAddr << " (expected " << remote <<
                 ") count: " << remoteChangeCnt_);
        }
        return false;
    }
    
    bool change_remote_address = false;
    
    // 1) this is very first packet
    if (recvCnt_ == 0) {
        change_remote_address = true;
    }
    else {
        // check current stream
        if (remoteChangeCnt_++ == 0) {
            lastRecvCnt_ = recvCnt_;
            checkTime_   = GetTimeMs();
        }
        
        // if current steam is dead for 2 seconds
        // then restart with new remote address
        if ((remoteChangeCnt_ % 20) == 0) {
            int64_t diff = GetTimeMs() - checkTime_;
            if (diff > 2000) {
                if (lastRecvCnt_ == recvCnt_) {
                    WLOG("Current stream ceased for " <<
                         diff << " ms");
                    change_remote_address = true;
                }
                else {
                    WLOG("Current stream (" << remote <<
                         ") is active (recv cnt: " << lastRecvCnt_ <<
                         " -> " << recvCnt_ << ", ignoring " <<
                         rRecvAddr << " data)");
                }
                remoteChangeCnt_ = 0; // reset the counter
            }
        }
    }
    
    if (change_remote_address) {
        MLOG("Remote Address adjusted by NAT - " <<
             rRecvAddr << " (current " << remote << ")");
        remoteIP_   = rRecvAddr.IPString();
        remotePort_ = rRecvAddr.Port();
        pConn_->SetRemoteAddress(remoteIP_, remotePort_);
    }
    else {
        if (0 < remoteChangeCnt_ && remoteChangeCnt_ < 11 &&
            rRecvAddr != lastNewRemoteAddr_) {
            WLOG("Detected different remote address - " <<
                 rRecvAddr << " (current " << remote <<
                 ") count: " << remoteChangeCnt_);
            lastNewRemoteAddr_ = rRecvAddr;
        }
        return false;
    }
    
    return true;
}
    
void UdpTransceiver::OnTimeOutEvent()
{
    pConn_->OnTransceiverTimeout();
}
    
} //namespace fuze
