//
//  TcpTransceiver.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/20/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <TcpTransceiver.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <Mapping.h>
#include <Data.h>
#include <HTTP.h>
#include <Server.h> // for getting Server::PORT
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_TCP, tcpCore_.log_ << __FUZE_FUNC__ << ": " << B)
#define _ELOG(A)   DEBUG_OUT(LEVEL_ERROR, AREA_BUF, log_ << __FUZE_FUNC__ << ": " << A)
#define _MLOG(A)   DEBUG_OUT(LEVEL_MSG,   AREA_BUF, log_ << __FUZE_FUNC__ << ": " << A)
#define _DLOG(A)   DEBUG_OUT(LEVEL_DEBUG, AREA_BUF, log_ << __FUZE_FUNC__ << ": " << A)

#ifndef WIN32

#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>

/* True iff e is an error that means an connect can be retried. */
#define EVUTIL_ERR_CONNECT_RETRIABLE(e)		\
        ((e) == EINTR || (e) == EINPROGRESS)
/* True iff e is an error that means the connection was refused */
#define EVUTIL_ERR_CONNECT_REFUSED(e)		\
        ((e) == ECONNREFUSED)

#else

#define EVUTIL_ERR_CONNECT_RETRIABLE(e)		\
        ((e) == WSAEWOULDBLOCK ||			\
        (e) == WSAEINTR ||                  \
        (e) == WSAEINPROGRESS ||			\
        (e) == WSAEINVAL)
#define EVUTIL_ERR_CONNECT_REFUSED(e)		\
        ((e) == WSAECONNREFUSED)

#endif


namespace fuze {

TcpFramer::TcpFramer()
{
    Clear();
}

void TcpFramer::SetMTU(uint32_t mtu)
{
    MTU_ = mtu;
}

void TcpFramer::Clear()
{
    spSendHeader_.reset();
    spSendBuffer_.reset();
    spRecvBuffer_.reset();
    
    MTU_       = 0; // no MTU restriction
    recvSize_  = 0;
    recvBytes_ = 0;
    headType_  = 0;
    log_[0]    = 0;
}
    
void TcpFramer::SetSendData(Buffer::Ptr spBuf)
{
    // first make a copy of it
    spSendBuffer_ = Buffer::makeShallowCopy(spBuf);
    
    // Buffer needs to implement a way to protect
    // data integrity and protection
    spSendHeader_ = Buffer::MAKE(HEADER_SIZE);
    spSendHeader_->setSize(HEADER_SIZE);
    uint8_t* p_head = spSendHeader_->getBuf();
    
    *p_head = Data::FUZE_MARK;
    p_head++;
    *p_head = DATA_HEAD;
    p_head++;
    uint32_t data_size = htonl(spBuf->size());
    memcpy(p_head, &data_size, sizeof(uint32_t));
}

bool TcpFramer::GetSendFrame(Buffer::Ptr& rspBuf)
{
    bool result = false;
    
    if (spSendHeader_) {
        rspBuf = spSendHeader_;
        spSendHeader_.reset();
        result = true;
    }
    else if (spSendBuffer_) {
        if (MTU_ > 0) {
            uint32_t buf_size = spSendBuffer_->size();
            if (buf_size <= MTU_) {
                _DLOG("send below MTU size (" << buf_size << "B)");
                rspBuf = spSendBuffer_;
                spSendBuffer_.reset();
            }
            else { // send by MTU size
                _DLOG("send by MTU size (" << MTU_ << "B)");
                Buffer::Ptr sp_fragment
                    = Buffer::makeShallowCopy(spSendBuffer_);
                sp_fragment->setSize(MTU_);
                rspBuf = sp_fragment;
                spSendBuffer_->pull(MTU_);
            }
        }
        else { // no MTU restriction
            _DLOG("send entire buffer (" << spSendBuffer_->size() << "B)");
            rspBuf = spSendBuffer_;
            spSendBuffer_.reset();
        }
        result = true;
    }
    
    return result;
}

void TcpFramer::SetRecvFrame(Buffer::Ptr spBuf)
{
    if (!spRecvBuffer_) {
        spRecvBuffer_ = spBuf;
        recvBytes_    = spBuf->size();
        _DLOG("First buffer (" << recvBytes_ << "B)");
    }
    else {
        uint8_t* p_frame    = spBuf->getBuf();
        uint32_t frame_size = spBuf->size();
        
        uint8_t* p_recv     = spRecvBuffer_->getBuf();
        uint32_t recv_size  = spRecvBuffer_->size();
        
        // if this is contiguous buffer then simply set the size
        if (p_frame == (p_recv + recv_size)) {
            if (recv_size != recvBytes_) {
                _ELOG("recv_size is not same as recvBytes_");
            }
            
            spRecvBuffer_->setSize(recv_size+frame_size);
            recvBytes_ += frame_size;
            
            _DLOG("CONTIGUOUS buffer (" << frame_size << "B) + " <<
                  recv_size << "B -> RecvBuffer " << recvBytes_ << "B");
        }
        else { // this is not contiguous buffer then copy
            // check if we have enough buffer to copy into
            uint32_t size_left = recv_size - recvBytes_;
            
            // if we have enough then copy into it
            if (size_left >= frame_size) {
                memcpy(p_recv + recvBytes_, p_frame, frame_size);
                recvBytes_ += frame_size;
                _DLOG("Copying " << frame_size <<
                      "B into buffer (" << size_left << "B)");
            }
            else { // we don't have enough room
                _DLOG("Not enough buffer (" << size_left <<
                      "B) (recvSize_: " << recvSize_ <<
                      "B) for frame " << frame_size << "B");
                
                uint32_t new_buf_size  = recvSize_;
                uint32_t required_size = recvBytes_ + frame_size;
                
                if (new_buf_size < required_size) {
                    new_buf_size = required_size;
                }
                
                Buffer::Ptr sp_new = Buffer::MAKE(new_buf_size);
                uint8_t* p_new = sp_new->getBuf();
                if (recvBytes_ > 0) {
                    memcpy(p_new, p_recv, recvBytes_);
                    p_new += recvBytes_;
                }
                memcpy(p_new, p_frame, frame_size);
                recvBytes_ += frame_size;
                _DLOG("Copying frame (" << frame_size << "B)");
                
                // reset the new buffer as recv buffer
                spRecvBuffer_ = sp_new;
            }
        }
    }
}

bool TcpFramer::GetRecvData(Buffer::Ptr& rspBuf, uint8_t& rHeadType)
{
    bool result = false;
    
    if (recvSize_ == 0) {
        // first determine the receiving size of data
        if (recvBytes_ >= HEADER_SIZE) {
            uint8_t* p_recv = spRecvBuffer_->getBuf();
            if (*p_recv == Data::FUZE_MARK) {
                p_recv++;
                headType_ = *p_recv;
                p_recv++;
                memcpy(&recvSize_, p_recv, sizeof(uint32_t));
                recvSize_ = ntohl(recvSize_);
                
                // check sanity
                if (headType_ == RATE_HEAD && recvSize_ != 7) {
                    _ELOG("Unexpected rate data size: " << recvSize_);
                    recvSize_ = 7;
                }
                
                if (headType_ == MAP_HEAD && recvSize_ != 10) {
                    _ELOG("Unexpected map data size: " << recvSize_);
                    recvSize_ = 10;
                }
                
                if (headType_ > 2 || recvSize_ > 3000000) {
                    _ELOG("Unexpected data (type: " << headType_ <<
                          ") size " << recvSize_ << "B");
                    spRecvBuffer_.reset();
                    recvBytes_ = 0;
                    recvSize_  = 0;
                    return false;
                }
                
                spRecvBuffer_->pull(HEADER_SIZE);
                recvBytes_ -= HEADER_SIZE;
                _DLOG("recvSize_ is " << recvSize_ <<
                      "B (recvBytes_: " << recvBytes_ << "B)");
            }
            else {
                _ELOG("Missing FuzeMark [" <<
                      Hex(p_recv, (recvBytes_ < 20 ? recvBytes_ : 20)) << "]")
                spRecvBuffer_.reset();
                recvBytes_ = 0;
                return false;
            }
        }
        else { // not enough - wait
            _DLOG("Not enough header " << recvBytes_ << "B - wait")
            return false;
        }
    }
    
    if (recvBytes_ >= recvSize_) {
        uint32_t size_before = spRecvBuffer_->size();
        
        rspBuf = Buffer::makeShallowCopy(spRecvBuffer_);
        rspBuf->setSize(recvSize_);
        spRecvBuffer_->pull(recvSize_);
        recvBytes_ -= recvSize_;
        recvSize_ = 0;
        rHeadType = headType_;
        
        _DLOG("Send to application " << rspBuf->size() <<
              "B (RecvBuffer - bytes left: " << recvBytes_-recvSize_ <<
              "B, size: " << size_before << "B -> " <<
              spRecvBuffer_->size() << "B)");
        
        // release the buffer if done
        if (recvBytes_ == 0 && spRecvBuffer_->size() == 0) {
            _DLOG("No more buffer left - reset RecvBuf")
            spRecvBuffer_.reset();
        }
        
        result = true;
    }
    
    return result;
}

void TcpFramer::SetDebugLog(const char *p)
{
    // tcpCore_.log_ was set by snprintf
    strncpy(log_, p, 64);
}
    
TcpTransceiver::TcpTransceiver(int transID)
    : Transceiver(transID)
    , socket_(INVALID_SOCKET)
    , connID_(INVALID_ID)
    , pConn_(0)
    , tcpCore_(*this)
    , bConnected_(false)
    , bUseFrame_(false)
    , pState_(StateSetupTcp::GetInstance())
    , setupMethod_(TcpTxrxState::SETUP_TCP)
    , lastSendError_(0)
    , lastDropTime_(0)
    , dropCnt_(0)
{
}

void TcpTransceiver::Reset()
{
    //
    // The thread safety is achieved by having
    // single libevent thread accessing pConn_
    // and resetting. Application won't have
    // access to pConn_ pointer
    //
    if (IsActive() == true) {
        MLOG("ACTIVE -> ZOMBIE");
        SetZombie();
        connID_     = INVALID_ID;
        pConn_      = 0;
        bConnected_ = false;
        
        tcpCore_.Reset();
        
        // If we established the connection through CURL's
        // proxy connect feature, then socket doesn't belong
        // to TcpTransceiver.  We should reset the ConnectInfo
        // to initiate curl_easy_cleanup process.
        if (spConnect_) {
            spConnect_.reset();
        }
        else {
            if (socket_ != INVALID_SOCKET) {
                evutil_closesocket(socket_);
            }
        }
        
        socket_ = INVALID_SOCKET;
        remote_.Clear();
        
        bUseFrame_ = false;
        tcpFramer_.Clear();
        
        pState_      = StateSetupTcp::GetInstance();
        setupMethod_ = TcpTxrxState::SETUP_TCP;
        
        spTlsCore_.reset();
        mapResponse_.clear();
        
        lastSendError_ = 0;
        lastDropTime_  = 0;
        dropCnt_       = 0;
    }
}
        
ConnectionType TcpTransceiver::ConnType()
{
    return CT_TCP;
}
    
void TcpTransceiver::SetConnectionID(int connID)
{
    if (connID != INVALID_ID) {
        MLOG("Attach to c" << connID);
        pConn_ = ResourceMgr::GetInstance()->GetConnection(connID);
    }
    else {
        MLOG("Detached from c" << connID_);
        pConn_ = 0;
    }
    
    connID_ = connID;
}
    
bool TcpTransceiver::Start()
{
    if (connID_ == INVALID_ID || !pConn_) {
        ELOG("Connection is not linked");
        return false;
    }
    
    const Address& remote = pConn_->GetRemoteAddress();
    
    if (remote.Valid() == false) {
        ELOG("Failed to get remote address");
        return false;
    }
    
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        ELOG("Failed to create socket")
        return false;
    }
    
    // set the log for tcpCore_
    snprintf(tcpCore_.log_, 64, "Tcp-C[c%d:s%d:r%d:%s] ", connID_,
            socket_, ID(), pConn_->GetName());

    SetSocketOption();
    
    bool bResult = false;
    
    // we connect the address
    sockaddr_in addr = remote.SocketAddress();
    
    if (connect(socket_, (sockaddr*)&addr, sizeof(sockaddr_in)) < 0) {
        
        bool failed = false;
        
		int e = evutil_socket_geterror(socket_);
		if (EVUTIL_ERR_CONNECT_RETRIABLE(e)) {
            MLOG("connect() is in progress on socket " << socket_ <<
                 " to " << remote.IPString() << ":" << remote.Port());
        }
        else {
            ELOG("Failed connect() to " << remote.IPString() << ":" <<
                 remote.Port() << " (" << evutil_socket_error_to_string(e) << ')');
            failed = true;
        }
        
        // handle success and fail event by libevent thread for failover
        // this is necessary to handle the case where local system is blocking
        // connect that it returns failure right away. 10 ms is chosen randomly
        // to hand off the failure logic to libevent for now.
        if (TransportImpl* p = TransportImpl::GetInstance()) {
            
            short    what    = EV_WRITE|EV_PERSIST;
            uint16_t timeout = 0;
            
            // if this is client, then trigger timeout
            if (p->IsAppServer() == false) {
                what |= EV_TIMEOUT;
                timeout = CONNECT_TIMEOUT;
                
                if (failed) {
                    timeout = 10;
                }
                else {
                    // if proxy is available then shortens timeout value
                    Address proxy;
                    if (get_http_proxy_address(proxy)) {
                        // Reduce to 500 ms if there seems to be a proxy
                        // This is safe guard to avoid any stale HTTP Proxy
                        // info where application failed to report the new
                        timeout = 500;
                    }
                }
                MLOG("Set timeout for " << timeout << " ms");
            }
            
            // use pWriteEvent to detect connected event first
            bResult = p->CreateEvent(tcpCore_.pWriteEvent_,
                                     socket_,
                                     what,
                                     OnLibEvent,
                                     this,
                                     timeout);
        }
    }
    else { // this would only happen when we are using blocked IO
        bConnected_ = true;

        pConn_->OnEvent(ET_CONNECTED, "Blocked IO");
        bResult = tcpCore_.StartReceive();
    }

    return bResult;
}

bool TcpTransceiver::Start(evutil_socket_t sock)
{
    if ((connID_ == INVALID_ID) || !pConn_) {
        ELOG("Connection is not linked");
        return false;
    }
    
    socket_      = sock;
    bConnected_  = true;

    // set the log for tcpCore_
    snprintf(tcpCore_.log_, 64, "Tcp-S[c%d:s%d:r%d:%s] ", connID_,
            socket_, ID(), pConn_->GetName());
    
    // sock is already set with nonblocking mode but we need
    // other stuff to set such as ToS and TCP_NODELAY
    SetSocketOption();

    sockaddr_in  peer;
    ev_socklen_t len = sizeof(peer);
    
    if (getpeername(sock, (sockaddr*)&peer, &len) == 0) {
        string src_ip = toStr(peer.sin_addr);
        uint16_t src_port = ntohs(peer.sin_port);
        
        MLOG("new TCP client connection from " <<
             src_ip << ":" << src_port);
        pConn_->SetRemoteAddress(src_ip, src_port);
    }
    else {
        ELOG("Error at getpeername()");
    }
    
    return tcpCore_.StartReceive();
}

void TcpTransceiver::PrepareProxyConnect()
{
    string   remote_addr;
    uint16_t remote_port;
    if (pConn_) {
        pConn_->GetOriginalRemoteAddress(remote_addr, remote_port);
    }
    
    const int BUF_SIZE = 255;
    char uri[BUF_SIZE+1];
    snprintf(uri, BUF_SIZE, "%s:%hu", remote_addr.c_str(), Server::PORT);
    
    spConnect_.reset(new ConnectInfo);
    spConnect_->tcpID_ = ID();
    spConnect_->remoteAddress_ = uri;
    
    if (ProxyConnector::Ptr p =
            TransportImpl::GetInstance()->GetProxyConnector()) {
        p->RequestConnection(spConnect_);
    }
    else {
        ELOG("Proxy connector is not available");
    }
}
    
void TcpTransceiver::StartAfterProxyConnect()
{
    if ((connID_ == INVALID_ID) || !pConn_) {
        ELOG("Connection is not linked");
        return;
    }
    
    if (!spConnect_) {
        ELOG("Proxy ConnectInfo is not available");
        return;
    }
    
    if (spConnect_->socket_ == INVALID_SOCKET) {
        ELOG("Proxy Connect failed");
        pConn_->OnEvent(ET_REFUSED);
        return;
    }
    
    socket_ = spConnect_->socket_;

    // set the log for tcpCore_
    snprintf(tcpCore_.log_, 64, "Tcp-C[c%d:s%d:r%d:%s] ", connID_,
            socket_, ID(), pConn_->GetName());
    
    // CURL uses blocking socket that we need to make it non-blocking
    // for purpose of using with libevent
    SetSocketOption();
    
    tcpCore_.StartReceive();
    
    MLOG("CURL created channel thru HTTP proxy");
    
    // by default we are skipping TCP_443 now (MQT-2200)
    SetState(TcpTxrxState::SETUP_TLS);
    
    pState_->OnConnected(this);
}

void TcpTransceiver::SetSocketOption()
{
    if (TransportImpl::GetInstance()->IsAppServer() == false) {
        // set read timeout value for tcpCore_ by default
        uint16_t read_timeout = READ_TIMEOUT;
        
        if (pConn_->IsPayloadType(Connection::RTP)) {
            read_timeout = RTP_TIMEOUT;
        }
        else if (pConn_->IsPayloadType(Connection::RTCP)) {
            read_timeout = RTCP_TIMEOUT;
        }
        else if (pConn_->IsPayloadType(Connection::SIP)) {
            read_timeout = 0;
        }
        
        if (read_timeout > 0) {
            tcpCore_.SetReadTimeout(read_timeout);
        }
    }
    
    evutil_make_socket_nonblocking(socket_);
    evutil_make_socket_closeonexec(socket_);
    
    int on = 1;
    ev_socklen_t on_len = sizeof(on);
    
    // enable no delay as default
    MLOG("Setting TCP_NODELAY");
    if (setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY,
                   (char*)&on, on_len) < 0) {
        ELOG("Failed to set TCP_NODELAY");
    }

#ifdef SO_KEEPALIVE
    on = 1;
    on_len = sizeof(on);
    if (setsockopt(socket_, SOL_SOCKET, SO_KEEPALIVE,
                   (char*)&on, on_len) < 0) {
        ELOG("Failed ot setsockopt KEEPALIVE");
    }
    
    on_len = sizeof(on);
    if (getsockopt(socket_, SOL_SOCKET, SO_KEEPALIVE,
                   (char*)&on, &on_len) < 0) {
        ELOG("Failed to getsockopt KEEPALIVE")
    }
    else {
        MLOG("SO_KEEPALIVE is " << (on == 1 ? "ON" : "OFF"));
    }
#endif
    
    // if original connection type is UDP then use NO_DELAY option
    if (pConn_->GetOriginalConnectionType() == CT_UDP) {
#ifndef WIN32
        MLOG("Setting ToS bit as 0xE0");
        int tos = 0xe0;
        if (setsockopt(socket_, IPPROTO_IP, IP_TOS,
                       (char*)&tos, sizeof(tos)) < 0) {
            ELOG("Failed to set ToS");
        }
#else
		HANDLE QOSHandle;
		QOS_VERSION version;

		version.MajorVersion = 1;
		version.MinorVersion = 0;

        if (!pfnQosCreateHandle_) {
			ELOG("qWAVE not available.");
		}
        else if (pfnQosCreateHandle_(&version, &QOSHandle) == 0) {
			WLOG("Couldn't create QOS handle err=" << GetLastError());
		}
        else {
			QOS_FLOWID flowid = 0;
			PriorityType pt;
			QOS_TRAFFIC_TYPE trafficType = QOSTrafficTypeBestEffort;

            if (pConn_) {
                if (pConn_->GetPriority(pt)) {
					switch (pt)
					{
					case PT_BACKGROUND:
						trafficType = QOSTrafficTypeBackground;
						break;
					case PT_EXCELLENTEFFORT:
						trafficType = QOSTrafficTypeExcellentEffort;
						break;
					case PT_AUDIOVIDEO:
						trafficType = QOSTrafficTypeAudioVideo;
						break;
					case PT_VOICE:
						trafficType = QOSTrafficTypeVoice;
						break;
					case PT_CONTROL:
					case PT_MAX_PRIORITY:
						trafficType = QOSTrafficTypeControl;
						break;
					default:
						trafficType = QOSTrafficTypeBestEffort;
						break;
					}
				}
			}

            if (!pfnQosAddSocketToFlow_) {
				ELOG("qWAVE not available.");
			}
			else if (pfnQosAddSocketToFlow_(QOSHandle, socket_, NULL, trafficType,
                                            QOS_NON_ADAPTIVE_FLOW, &flowid) == 0) {
				MLOG("Not allowed to add socket to QOS flow [" << GetLastError() << "]");
			}
            else {
				MLOG("Successfully added socket to QOS flow");
			}
		}
#endif
    }
    
#ifdef SO_NOSIGPIPE
    on = 1;
    if (setsockopt(socket_, SOL_SOCKET, SO_NOSIGPIPE,
                   (char*)&on, sizeof(on)) < 0) {
        ELOG("Failed to set SO_NOSIGPIPE errno " << errno);
    }
#endif
    
    int snd_size, rcv_size;
    ev_socklen_t len = sizeof(int);
    getsockopt(socket_, SOL_SOCKET, SO_SNDBUF, (char*)&snd_size, &len);
    getsockopt(socket_, SOL_SOCKET, SO_RCVBUF, (char*)&rcv_size, &len);
    MLOG("get socket buffer size: recv " << rcv_size << ", send " << snd_size);

    bool is_rtp = pConn_->IsPayloadType(Connection::RTP);
    
    if (is_rtp) {
        snd_size = 4500; // about 500 ms - 25 RTP packets of G.722
        setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, (char*)&snd_size, sizeof(int));
        MLOG("RTP Connection - setting send socket buffer size: " << snd_size << "B");
    }
    else {
        if (snd_size < 50000) {
            snd_size = 50000;
            setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, (char*)&snd_size, sizeof(int));
            MLOG("increase send socket buffer size: " << snd_size << "B");
        }
    }
    
    if (rcv_size < 50000) {
        rcv_size = 50000;
        setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, (char*)&rcv_size, sizeof(int));
        MLOG("increase recv socket buffer size: " << rcv_size << "B");
    }
}
    
void TcpTransceiver::OnLibEvent(evutil_socket_t sock, short what, void* pArg)
{
    DEBUG_OUT(LEVEL_DEBUG, AREA_COM, "socket " << sock << " has event " <<
              (what & EV_READ ? "READ" : "") <<
              (what & EV_WRITE ? "WRITE" : ""));
    
    if (TcpTransceiver* p = reinterpret_cast<TcpTransceiver*>(pArg)) {
        if (p->socket_ != sock) {
            DEBUG_OUT(LEVEL_ERROR, AREA_COM, "socket mismatch");
            return;
        }

        try {
            if (what & EV_WRITE) {
                p->OnConnectedEvent();
            }
            if (what & EV_TIMEOUT) {
                
                // timeout here means we didn't connect
                // remove the timer so that it won't trigger again
                event_free(p->tcpCore_.pWriteEvent_);
                p->tcpCore_.pWriteEvent_ = 0;
                
                // timeout while we tried to connect, this must be due to
                // firewall dropping our SYN packet to far end
                if (p->pConn_) {
                    p->pConn_->OnTransceiverTimeout();
                }
            }
        }
        catch (std::exception& ex) {
            DEBUG_OUT(LEVEL_ERROR, AREA_COM, "TCP::OnLibEvent: exception - " <<
                      ex.what());
        }
        catch (...) {
            DEBUG_OUT(LEVEL_ERROR, AREA_COM, "TCP::OnLibEvent: unknown exception");
        }
    }
}
    
bool TcpTransceiver::Send(Buffer::Ptr spBuffer)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }

    if (bConnected_ == false) {
        uint64_t curr_tick = GetTimeMs();
        if (curr_tick - lastSendError_ >= 3000) {
            MLOG("not connected - TcpTxrxState: " <<
                 toStr(pState_->GetType()));
            lastSendError_ = curr_tick;
        }
        return false;
    }

    // impose queue size limit    
    size_t   q_size;
    uint32_t q_buf_size;
    tcpCore_.GetSendQInfo(q_size, q_buf_size);
    
    if (q_buf_size > Q_LIMIT) {
        dropCnt_++;
        int64_t curr = GetTimeMs();
        if (curr - lastDropTime_ > 1000) {
            ELOG("sendQ_ reached the limit (" << q_buf_size << " bytes or " <<
                 q_size << ") - " << dropCnt_ << " dropped in " <<
                 (lastDropTime_ ? (curr - lastDropTime_) : 0) << " ms");
            dropCnt_ = 0;
            lastDropTime_ = curr;
        }
        
        return false;
    }
    
    if (bUseFrame_) {
        // protect sequencing the data into sendQ
        MutexLock scoped(&sendLock_);
        tcpFramer_.SetSendData(spBuffer);
        while (tcpFramer_.GetSendFrame(spBuffer)) {
            pState_->Send(this, spBuffer);
        }
    }
    else {
        pState_->Send(this, spBuffer);
    }
    
    return true;
}

void TcpTransceiver::SendStat(uint8_t type, uint16_t rateKbps, uint32_t seqNum)
{
    if (bUseFrame_) {
        const uint32_t payload_len = 7;
        uint32_t total_len = TcpFramer::HEADER_SIZE + payload_len;
        Buffer::Ptr sp_buf = Buffer::MAKE(total_len);
        sp_buf->setSize(total_len);
        
        uint8_t* p_head = sp_buf->getBuf();
        
        *p_head = Data::FUZE_MARK;
        p_head++;
        *p_head = TcpFramer::RATE_HEAD;
        p_head++;
        
        uint32_t net_len = htonl(payload_len);
        memcpy(p_head, &net_len, sizeof(uint32_t));
        p_head += sizeof(uint32_t);
        
        *p_head = type;
        p_head++;
        
        rateKbps = htons(rateKbps);
        memcpy(p_head, &rateKbps, sizeof(uint16_t));
        p_head += sizeof(uint16_t);
        
        seqNum = htonl(seqNum);
        memcpy(p_head, &seqNum, sizeof(uint32_t));

        // race with app thread here (only for WYSWYG mode)
        MutexLock scoped(&sendLock_);
        pState_->Send(this, sp_buf);
    }
}
    
void TcpTransceiver::OnConnectedEvent()
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (bConnected_) {
        ELOG("Already connected");
        return;
    }
    
    // check if we have succeeded
    int error = 0;
    ev_socklen_t len = sizeof(error);
    
    EventType event = ET_FAILED;
    
    if (getsockopt(socket_, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0) {
        if (error == 0) {
            DLOG("TCP connection established");
            event = ET_CONNECTED;
            
            sockaddr_in  local;
            len = sizeof(local);
            
            if (getsockname(socket_, (sockaddr*)&local, &len) == 0) {
                if (pConn_) {
                    pConn_->SetLocalAddress(toStr(local.sin_addr),
                                            ntohs(local.sin_port));
                }
            }
            else {
                ELOG("Error at getsockname()");
            }
        }
        else {
            if (EVUTIL_ERR_CONNECT_RETRIABLE(error)) {
                MLOG("Retrying connect: " <<
                     evutil_socket_error_to_string((error)));
                return; // try again
            }
            EVUTIL_SET_SOCKET_ERROR(error);
            if (EVUTIL_ERR_CONNECT_REFUSED(error)) {
                event = ET_REFUSED;
            }
        }
    }
    else {
        ELOG("getsockopt error");
    }

    //
    // instead of deleting the write event, we are freeing
    // event here so that tcpCore_ will create another write
    // event associated with its own callback method to handle
    // send/recv operation within. This will trigger
    // TcpCore::OnDataReceived callback to be used
    //
    event_free(tcpCore_.pWriteEvent_);
    tcpCore_.pWriteEvent_ = 0;

//#define FALLBACK_TEST
#ifdef  FALLBACK_TEST
    if (strncmp(pConn_->GetName(), "RTP", 3) == 0 ||
        strncmp(pConn_->GetName(), "SIP", 3) == 0) {
        if (setupMethod_ < TcpTxrxState::SETUP_HTTP_TLS) {
            event = ET_REFUSED;
        }
    }
#endif
    
    if (event == ET_CONNECTED) {
        tcpCore_.StartReceive();
        pState_->OnConnected(this);
    }
    else {
        if (pConn_) {
            pConn_->OnEvent(event, "connect failure");
        }
    }
}

evutil_socket_t TcpTransceiver::Socket()
{
    return socket_;
}

uint32_t TcpTransceiver::OnDataReceived(Buffer::Ptr spBuf)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return 0;
    }
    
    if ((connID_ == INVALID_ID) || !pConn_) {
        ELOG("Connection is not bound");
        return 0;
    }
    
    return pState_->OnDataReceived(this, spBuf);
}
    
void TcpTransceiver::OnBytesSent(uint32_t bytesSent)
{
    if (pConn_) {
        pConn_->OnBytesSent(bytesSent);
    }
}

void TcpTransceiver::OnBytesRecv(uint32_t bytesRecv)
{
    if (pConn_) {
        uint32_t recv_cnt = pConn_->OnBytesRecv(bytesRecv);
        
        // if we are server using TcpFraming then
        // send mapped address and unique id once we received
        // first message from far end
        if ((recv_cnt == 1) && bUseFrame_ &&
            TransportImpl::GetInstance()->IsAppServer()) {
            if (pState_->GetType() == TcpTxrxState::DATA_OVER_TLS ||
                pState_->GetType() == TcpTxrxState::TCP) {
                SendMapData();
            }
        }
    }
}
    
void TcpTransceiver::OnDisconnect()
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    // TODO: THREAD POOL
    if (pConn_) {
        pConn_->OnEvent(ET_DISCONNECTED, "Far end closed");
    }
}

void TcpTransceiver::OnReadError(int error)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    EventType type = ET_FAILED;
    if (EVUTIL_ERR_CONNECT_REFUSED(error)) {
        type = ET_REFUSED;
    }

    if (pConn_) {
        pConn_->OnEvent(type, "Tcp Read Error");
    }
}

void TcpTransceiver::OnWriteError(int error)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (pConn_) {
        pConn_->OnEvent(ET_FAILED, "Tcp Write Error");
    }
}

void TcpTransceiver::OnReadTimeout()
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (pConn_) {
        pConn_->OnTransceiverTimeout();
    }
}
    
void TcpTransceiver::OnDataEncrypted(Buffer::Ptr spData)
{
    tcpCore_.Send(spData);
}
    
void TcpTransceiver::OnDataDecrypted(Buffer::Ptr spData)
{
    if (pState_->GetType() == TcpTxrxState::SETUP_MAP_TLS) {
        OnMapResponse(spData);
    }
    else {
        OnDataProcessed(spData);
    }
}

void TcpTransceiver::OnInternalError()
{
    if (pConn_) {
        pConn_->OnEvent(ET_FAILED, "TLS Internal Error");
    }
}
    
void TcpTransceiver::SetState(TcpTxrxState::Type type, bool initial)
{
    MLOG(toStr(pState_->GetType()) << " -> " << toStr(type));
    
    if (initial) {
        setupMethod_ = type;
    }
    
    switch (type)
    {
    case TcpTxrxState::TCP:
        pState_ = StateTcp::GetInstance();
        break;
    case TcpTxrxState::UDP_OVER_TCP:
        pState_ = StateUdpOverTcp::GetInstance();
        break;
    case TcpTxrxState::TLS:
        pState_ = StateTls::GetInstance();
        break;
    case TcpTxrxState::DATA_OVER_TLS:
        pState_ = StateDataOverTls::GetInstance();
        if (bUseFrame_) {
            tcpFramer_.SetMTU(MAX_MTU_SIZE);
        }
        break;
    case TcpTxrxState::SETUP_TCP:
        pState_ = StateSetupTcp::GetInstance();
        break;
    case TcpTxrxState::SETUP_TCP_443:
        pState_ = StateSetupTcpPort443::GetInstance();
        break;
    case TcpTxrxState::SETUP_TLS:
        pState_ = StateSetupTls::GetInstance();
        break;
    case TcpTxrxState::SETUP_MAP_TLS:
        pState_ = StateSetupMapTls::GetInstance();
        break;
    case TcpTxrxState::SETUP_HTTP:
    case TcpTxrxState::SETUP_HTTP_TLS:
        pState_ = StateHttpTls::GetInstance(); // dummy instance
        break;
    default:
        ELOG("Unknown type: " << toStr(type));
    }
}

TcpTxrxState::Type TcpTransceiver::GetStateType()
{
    return pState_->GetType();
}

TcpTxrxState::Type TcpTransceiver::GetSetupMethodType()
{
    return setupMethod_;
}

void TcpTransceiver::OnDataProcessed(Buffer::Ptr spBuf)
{
    if (!pConn_) return;
    
    if (bUseFrame_) {
        tcpFramer_.SetRecvFrame(spBuf);
        uint8_t head_type = 0;
        while (tcpFramer_.GetRecvData(spBuf, head_type)) {
            if (head_type == TcpFramer::DATA_HEAD) {
                pConn_->OnData(spBuf);
            }
            else if (head_type == TcpFramer::RATE_HEAD) {
                pConn_->OnStatReceived(spBuf);
            }
            else {
                pConn_->OnMapReceived(spBuf);
            }
        }
    }
    else {
        pConn_->OnData(spBuf);
    }
}
    
void TcpTransceiver::EnableTcpFramer()
{
    MLOG("Enabling WYSWYG for application");
    
    bUseFrame_ = true;

    tcpFramer_.SetDebugLog(tcpCore_.log_);
    
    if (pState_->GetType() == TcpTxrxState::DATA_OVER_TLS) {
        tcpFramer_.SetMTU(MAX_MTU_SIZE);
    }
}

void TcpTransceiver::SendMapData()
{
    const uint32_t payload_len = 10;
    uint32_t total_len = TcpFramer::HEADER_SIZE + payload_len;
    Buffer::Ptr sp_buf = Buffer::MAKE(total_len);
    sp_buf->setSize(total_len);
    
    uint8_t* p_head = sp_buf->getBuf();
    
    *p_head = Data::FUZE_MARK;
    p_head++;
    *p_head = TcpFramer::MAP_HEAD;
    p_head++;
    
    uint32_t net_len = htonl(payload_len);
    memcpy(p_head, &net_len, sizeof(uint32_t));
    p_head += sizeof(uint32_t);
    
    // add address and random key
    const Address& r_remote = pConn_->GetRemoteAddress();
    
    in_addr ip = r_remote.IPNum();
    memcpy(p_head, &ip, sizeof(uint32_t));
    p_head += sizeof(uint32_t);
    
    uint16_t port = htons(r_remote.Port());
    memcpy(p_head, &port, sizeof(uint16_t));
    p_head += sizeof(uint16_t);
    
    uint32_t rand_num = rand();
    MLOG("Sending MAP_DATA to " << r_remote << " key: " << rand_num);
    rand_num = htonl(rand_num);
    memcpy(p_head, &rand_num, sizeof(uint32_t));
    
    // race with app thread here (only for WYSWYG mode)
    MutexLock scoped(&sendLock_);
    pState_->Send(this, sp_buf);
}
    
void TcpTransceiver::GetSendQInfo(size_t& rNum, uint32_t& rBufSize)
{
    tcpCore_.GetSendQInfo(rNum, rBufSize);
}

uint32_t TcpTransceiver::GetSendRetryCount()
{
    return tcpCore_.GetSendRetryCount();
}
    
Buffer::Ptr TcpTransceiver::MakeMapRequest()
{
    using tp::HttpRequest;
    
    string   remote_addr;
    uint16_t remote_port = 0;
    
    ConnectionType type = CT_UDP;
    if (pConn_) {
        pConn_->GetOriginalRemoteAddress(remote_addr, remote_port);
        type = pConn_->GetOriginalConnectionType();
    }
    
    Mapping::Ptr sp_map;
    sp_map.reset(new Mapping(type, remote_addr, remote_port));
    sp_map->SetID(tcpCore_.log_);
    
    HttpRequest req(HttpRequest::POST);
    req.SetRequestURI(Mapping::RESOURCE_NAME);
    req.SetMsgBody(sp_map);
    
    return req.Serialize();
}

uint32_t TcpTransceiver::OnMapResponse(Buffer::Ptr spBuf)
{
    if (!pConn_) {
        ELOG("Connection is detached");
        return spBuf->size();
    }
    
    uint8_t* p_buf   = spBuf->getBuf();
    uint32_t buf_len = spBuf->size();
    
    mapResponse_.append((char*)p_buf, buf_len);
    
    p_buf   = (uint8_t*)mapResponse_.c_str();
    buf_len = (uint32_t)mapResponse_.size();
    
    uint32_t msg_len = msg::get_length(p_buf, buf_len);
    if (msg_len > 0) {
        msg::Type msg_type = msg::get_type(p_buf, buf_len);
        DLOG("Received: " << toStr(msg_type) << " (" << msg_len << "B)");
        
        // if we have not connected to far end then we expect the
        // first response to be mapping response message
        if ((msg_type == msg::HTTP) &&
            (msg::is_http_response(p_buf, buf_len))) {
            
            tp::HttpResponse rsp;
            rsp.Parse(p_buf, buf_len);
            
            uint32_t resp_code = rsp.GetResponseCode();
            if (200 <= resp_code && resp_code < 300) {
                ConnectionType orig = pConn_->GetOriginalConnectionType();
                
                MLOG("Successfully mapped at far end (requested: " <<
                     toStr(orig) << ", connecting Method: " <<
                     toStr(setupMethod_)  << ")");
                
                // if mapping happened over TLS then use DATA over TLS
                if ((setupMethod_ == TcpTxrxState::SETUP_TLS) ||
                    (setupMethod_ == TcpTxrxState::SETUP_HTTP_TLS)) {
                    SetState(TcpTxrxState::DATA_OVER_TLS);
                }
                else {
                    if (orig == CT_UDP) {
                        SetState(TcpTxrxState::UDP_OVER_TCP);
                    }
                    else if (orig == CT_TCP) {
                        SetState(TcpTxrxState::TCP);
                    }
                    else if (orig == CT_TLS) { // we shouldn't come here
                        ELOG("Unexpected state transition");
                        SetState(TcpTxrxState::DATA_OVER_TLS);
                    }
                }
                
                // clear stat as we are now connected
                pConn_->ClearStat();
                
                // set connected flag only after we switched Tcp state
                bConnected_ = true;
                pConn_->OnEvent(ET_CONNECTED, "Connection mapped");
            }
        }
        
        if (bConnected_ == false) {
            ELOG("Failed to map connection");
            pConn_->OnEvent(ET_FAILED, "Failed to map connection");
        }
    }
    else {
        MLOG("Not enough message: " << buf_len << "B");
    }
    
    return msg_len;
}
    
} // namespace fuze
