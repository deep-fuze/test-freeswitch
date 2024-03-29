//
//  DtlsTransceiver.cpp
//  FuzeTransport
//
//  Created by Tim Na on 12/4/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <DtlsTransceiver.h>
#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <string.h>
#include <Log.h>

#ifdef __linux__
#include <string.h> // memset
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_UDP, "DTLS[c" << connID_ << ":s" << socket_ << ":" << pName_ << "] " << __FUZE_FUNC__ << ": " << B)

#ifndef WIN32
#include <errno.h>
#include <string.h>
/* True iff e is an error that means a read/write operation can be retried. */
#define EVUTIL_ERR_RW_RETRIABLE(e) \
((e) == EINTR || (e) == EAGAIN)
#define EVUTIL_ERR_CONNECT_REFUSED(e) \
((e) == ECONNREFUSED)
#else

#include <ws2ipdef.h>
#include <WinSock2.h>

#define EVUTIL_ERR_RW_RETRIABLE(e) \
((e) == WSAEWOULDBLOCK || (e) == WSAEINTR)
#define EVUTIL_ERR_CONNECT_REFUSED(e) \
((e) == WSAECONNREFUSED)
#endif

namespace fuze {

DtlsTransceiver::DtlsTransceiver(int transID)
    : Transceiver(transID)
{
    Init();
}

void DtlsTransceiver::Init()
{
    connType_     = CT_DTLS_CLIENT;
    connID_       = INVALID_ID;
    pConn_        = 0;
    socket_       = INVALID_SOCKET;
    pDtlsCore_    = 0;
    pReadEvent_   = 0;
    readTimeout_  = 0;
    pWriteEvent_  = 0;
    writeAdded_   = false;
    dtlsState_    = INIT;
    logCnt_       = 0;
    stunCnt_      = 0;
    lastStunTime_ = 0;
    flowID_       = 0;

    memset(pName_, 0, 16);

    MutexLock scoped(&qLock_);
    queue<Buffer::Ptr> emptyQ;
    swap(sendQ_, emptyQ);
}

void DtlsTransceiver::Reset()
{
    if (IsActive() == true) {
        MLOG("ACTIVE -> ZOMBIE");
        SetZombie();

        // To deallocate an event, call event_free(). It is safe to call
        // event_free() on an event that is pending or active: doing so makes
        // the event non-pending and inactive before deallocating it.
        if (pReadEvent_)  event_free(pReadEvent_);
        if (pWriteEvent_) event_free(pWriteEvent_);

        if (socket_ != INVALID_SOCKET) {
            if (TransportImpl* p = TransportImpl::GetInstance()) {
                if (flowID_ != 0) {
                    p->UnsetQoSTag(socket_, flowID_);
                }
            }
            evutil_closesocket(socket_);
        }

        if (pDtlsCore_) delete pDtlsCore_;

        srtp_.Reset();

        Init();
    }
}

ConnectionType DtlsTransceiver::ConnType()
{
    return connType_;
}

void DtlsTransceiver::SetConnectionID(int connID)
{
    if (connID != INVALID_ID) {
        connID_ = connID;
        pConn_ = ResourceMgr::GetInstance()->GetConnection(connID);
        memcpy(pName_, pConn_->GetName(), 15);
    }
}

void DtlsTransceiver::SetConnectionType(ConnectionType eType)
{
    connType_ = eType;
}

void DtlsTransceiver::OnDataEncrypted(Buffer::Ptr spData)
{
#if 0 // Testing retransmission logic in FuzeTransportTest-Mac
    if (connType_ == CT_DTLS_SERVER) {
        static int num;
        if ((num++ % 2) == 0) {
            MLOG("Packet " << num << " dropped (" << spData->size() << "B)");
            return;
        }
    }
    else {
        static int num;
        if ((num++ % 2) == 0) {
            MLOG("Packet " << num << " dropped (" << spData->size() << "B)");
            return;
        }
    }
#endif

    SendData(spData, pConn_->GetRemoteAddress());
}

void DtlsTransceiver::OnDataDecrypted(Buffer::Ptr spData)
{
    pConn_->OnData(spData);
}

void DtlsTransceiver::SendData(Buffer::Ptr spData, const Address& rRemote)
{
    long sent = 0;

    char* p_buf = (char*)spData->getBuf();
    long  size  = spData->size();

    if (const char* p = LogMsg(p_buf, size)) {
        MLOG("--- " << p << " (" << size << "B) ---> " << rRemote <<
             " (msg cnt: " << stunCnt_ << ")");
    }
    else {
        DLOG("--- " << Hex((uint8_t*)p_buf, 12) << " (" << size << "B) ---> " << rRemote);
    }

    if (connType_ == CT_DTLS_CLIENT) {
        sent = send(socket_, p_buf, size, 0);
    }
    else {
        sent = sendto(socket_, p_buf, size, 0,
                      rRemote.SockAddr(), rRemote.SockAddrLen());
    }

    if (sent == size) {
        pConn_->OnBytesSent((uint32_t)sent);
    }
    else {
        ELOG("Sent only " << sent << "B out of " << size << "B data");
    }
}

const char* DtlsTransceiver::LogMsg(const char* pMsg, uint32_t size)
{
    using namespace stun;

    const char* p = 0;
    switch (*pMsg)
    {
    case 20: p = "ChangeCipherSpec"; break;
    case 21: p = "Alert";            break;
    case 22: p = "Handshake";        break;
    case 24: p = "Heartbeat";        break;
    default:
        if (IsStun(pMsg, size)) {
            // print every 100th of stun message
            if ((stunCnt_ % 100) == 1) {
                p = toStr(GetType(pMsg, size));
            }
        }
    }
    return p;
}

void DtlsTransceiver::OnInternalError()
{
    event_del(pReadEvent_);
    RemoveWriteEvent();

    pConn_->OnEvent(ET_FAILED);
}

Buffer::Ptr DtlsTransceiver::GetTlsBuffer(uint32_t bufSize)
{
    if (pConn_) {
        return pConn_->GetBuffer(bufSize);
    }
    else {
        return Buffer::MAKE(bufSize);
    }
}

bool DtlsTransceiver::Start()
{
    if (connID_ == INVALID_ID || !pConn_) {
        ELOG("Connection is not linked");
        return false;
    }

    // DTLS requires handshake to be done first
    //
    // DTLS client
    //  1. connect to far end using remote address
    //  2. do the handshake
    //  3. once connected send CONNECTED event
    //
    // DTLS server
    //  1. wait until client is connected
    //  2. do the handshake
    //  3. once connected send CONNECTED event

    bool bResult = false; // boolean to indicate if socket is binded

    Address addr;

    if (connType_ == CT_DTLS_CLIENT) {
        addr = pConn_->GetRemoteAddress();
        if (addr.Valid() == false) {
            ELOG("No remote IP to connect");
            return false;
        }
    }
    else { // CT_DTLS_SERVER
        addr = pConn_->GetLocalAddress();
        if (addr.Valid() == false) {
            ELOG("No Local address is not set");
            return false;
        }

        // check if the port was reserved in reservation pool
        if (PortReserve::Ptr sp_rsv
                = TransportImpl::GetInstance()->GetReservedPort(addr.Port())) {
            MLOG("Found reserved port: " << addr.Port() <<
                 " (s:" << sp_rsv->sock_ << ")");
            socket_ = sp_rsv->sock_;
            StopTimer(sp_rsv, sp_rsv->timerID_);
            bResult = true; // indicate we have bound socket already
        }
    }

    // if we don't have reserved socket then create one
    if (!bResult) {
        socket_ = socket(addr.IPType(), SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET) {
            ELOG("Failed to create socket")
            return false;
        }
    }

    if (connType_ == CT_DTLS_SERVER) {
        if (!bResult) {
            if (::bind(socket_, addr.SockAddr(), addr.SockAddrLen()) == 0) {
                bResult = true;
            }
        }
    }
    else { // DTLS client don't bind socket
        if (::connect(socket_, addr.SockAddr(), addr.SockAddrLen()) == 0) {

            // if connected UDP is used then get local address
            // that is set by operating system
            sockaddr_storage local;
            ev_socklen_t     len = sizeof(sockaddr_storage);

            if (getsockname(socket_, (sockaddr*)&local, &len) == 0) {
                if (pConn_) {
                    Address local_addr(local);
                    MLOG("local address:" << local_addr);
                    pConn_->SetLocalAddress(local_addr.IPString(),
                                            local_addr.Port());
                }
            }
            else {
                ELOG("Error at getsockname()");
            }

            bResult = true;
        }
    }

    const char* p = (connType_ == CT_DTLS_CLIENT ?
                     "DTLS Client connect" :
                     "DTLS Server listen");

    if (bResult) {
        MLOG(p << " (s" << socket_ << ") on " << addr);

        evutil_make_socket_nonblocking(socket_);
        evutil_make_listen_socket_reuseable(socket_);

        TransportImpl::GetInstance()->SetQoSTag(socket_, pConn_, flowID_);

        if (pDtlsCore_) {
            ELOG("TlsCore exists already!");
            delete pDtlsCore_;
        }

        bool server = (connType_ == CT_DTLS_SERVER);
        pDtlsCore_ = new (std::nothrow) DtlsCore(*this, server);
        if (pDtlsCore_) {
            pDtlsCore_->Init();

            // DTLS client initiates the handshake after stun auth - create write event
            //      sending stun message will trigger read event
            // DTLS server waits for first handshake - just create read event
            if (connType_ == CT_DTLS_CLIENT) {
                bResult = SetWriteEvent();
            }
            else {
                bResult = SetReadEvent();
            }
        }
    }
    else {
        int e = evutil_socket_geterror(socket_);
        ELOG(p << " failed to set " << addr << " (" <<
             evutil_socket_error_to_string(e) << ") errno=" << e);
    }

    return bResult;
}

bool DtlsTransceiver::SetReadEvent(uint16_t timeout)
{
    bool bResult = false;

    // We'll always have read event but may have different timeout.
    // Free the read event to set different timeout value
    if (pReadEvent_) {
        // if timeout value is same then just return true
        if (readTimeout_ == timeout) return true;
        event_free(pReadEvent_);
        pReadEvent_ = 0;
    }

    if (TransportImpl* p = TransportImpl::GetInstance()) {

        readTimeout_ = timeout;

        short what = EV_READ|EV_PERSIST;

        // if this is client, then trigger timeout
        if (timeout > 0) {
            MLOG("timeout " << timeout << "ms");
            what |= EV_TIMEOUT;
        }
        else {
            MLOG("no timeout");
        }

        bResult = p->CreateEvent(pReadEvent_, socket_, what,
                                 OnLibEvent, this, timeout);
    }

    return bResult;
}

bool DtlsTransceiver::SetWriteEvent()
{
    bool bResult = false;

    if (pWriteEvent_) {
        if (!writeAdded_) {
            event_add(pWriteEvent_, 0);
            writeAdded_ = true;
        }
        bResult = true;
    }
    else {
        if (TransportImpl* p = TransportImpl::GetInstance()) {
            writeAdded_ = p->CreateEvent(pWriteEvent_, socket_,
                                         EV_WRITE|EV_PERSIST,
                                         OnLibEvent, this);
            bResult = writeAdded_;
        }
    }

    return bResult;
}

void DtlsTransceiver::OnLibEvent(evutil_socket_t sock, short what, void* pArg)
{
    DEBUG_OUT(LEVEL_DEBUG, AREA_COM, "s" << sock <<
              " has event " << (what & EV_READ ? "READ" : "") <<
              (what & EV_WRITE ? "WRITE" : "") <<
              (what & EV_TIMEOUT ? "TIMEOUT" : ""));

    if (DtlsTransceiver* p = reinterpret_cast<DtlsTransceiver*>(pArg)) {

        if (p->IsActive() == false) return;
        if (p->socket_ != sock)     return;
        if (p->connID_ == INVALID_ID || p->pConn_ == 0) return;

        try {
            if (what & EV_READ)    p->OnReadEvent();
            if (what & EV_WRITE)   p->OnWriteEvent();
            if (what & EV_TIMEOUT) p->OnTimeOutEvent();
        }
        catch (const std::exception& ex) {
            DEBUG_OUT(LEVEL_ERROR, AREA_COM, "exception: " << ex.what());
        }
        catch (...) {
            DEBUG_OUT(LEVEL_ERROR, AREA_COM, "unknown exception");
        }
    }
}

bool DtlsTransceiver::Send(Buffer::Ptr spBuffer)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }

    if ((socket_ == INVALID_SOCKET) || !pConn_) {
        return false;
    }

    if (dtlsState_ != ESTABLISHED) {
        if ((logCnt_++ % 50) == 0) {
            WLOG("Connection is not established (cnt: " << logCnt_ << ")");
        }
        return false;
    }

    MutexLock scoped(&qLock_);
    sendQ_.push(spBuffer);

    SetWriteEvent();

    return true;
}

bool DtlsTransceiver::Send(const uint8_t* buf, size_t size)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }

    if ((socket_ == INVALID_SOCKET) || !pConn_) {
        return false;
    }

    if (dtlsState_ != ESTABLISHED) {
        if ((logCnt_++ % 50) == 0) {
            WLOG("Connection is not established (cnt: " << logCnt_ << ")");
        }
        return false;
    }

    EncryptAndSend((uint8_t*)buf, size);
    return true;
}

void DtlsTransceiver::OnReadEvent()
{
    long recv_bytes = 0;

    do {
        sockaddr_storage saddr;

        if (connType_ == CT_DTLS_CLIENT) {
            recv_bytes = recv(socket_, buffer_, MAX_UDP_SIZE, 0);
        }
        else {
            ev_socklen_t slen = sizeof(sockaddr_storage);

            recv_bytes = recvfrom(socket_, buffer_, MAX_UDP_SIZE, 0,
                                 (sockaddr*)&saddr, &slen);
        }

        Address remote_addr(saddr);
        if (connType_ == CT_DTLS_CLIENT) {
            remote_addr = pConn_->GetRemoteAddress();
        }

        if (recv_bytes > 0) {
            pConn_->OnBytesRecv((uint32_t)recv_bytes);

            bool is_stun = stun::IsStun(buffer_ , recv_bytes);
            if (is_stun) {
                stunCnt_++;
            }

            if (const char* p = LogMsg(buffer_, recv_bytes)) {
                MLOG("<--- " << p << " (" << recv_bytes << "B) --- " <<
                     remote_addr << " (msg cnt: " << stunCnt_ << ")");
            }
            else {
                DLOG("<--- " << Hex((uint8_t*)buffer_, 12) << " (" <<
                     recv_bytes << "B) --- " << remote_addr);
            }

            // if this is stun packet then process it as best we know how
            if (is_stun) {
                string local_user, local_pwd;
                pConn_->GetLocalIceCredential(local_user, local_pwd);

                bool no_stun_log = ((stunCnt_ % 100) != 1);

                if (stun::GetType(buffer_, recv_bytes) == stun::REQUEST &&
                    stun::GetMethod(buffer_, recv_bytes) == stun::BINDING &&
                    stun::Validate(buffer_, recv_bytes, local_pwd, no_stun_log)) {

                    if (connType_ == CT_DTLS_SERVER) {
                        Address curr_remote = pConn_->GetRemoteAddress();
                        if (dtlsState_ == INIT && !curr_remote.Valid()) {
                            MLOG("remote address set by first packet " << remote_addr);
                            pConn_->SetRemoteAddress(remote_addr.IPString(), remote_addr.Port());
                            lastStunTime_ = GetTimeMs();
                        }
                        else {
                            // For server, we're connected already check where we received data
                            // For client, we are doing connected mode that that won't happen
                            if (curr_remote != remote_addr) {
                                // if stun request stopped coming from current remote
                                // for more than 5 seconds than use new incoming one
                                int64_t time_passed = (GetTimeMs() - lastStunTime_);
                                if (time_passed > 5000) {
                                    ELOG("Expiring current remote " << remote_addr <<
                                         " and using new remote " << curr_remote <<
                                         " due to no refresh for " << time_passed << " ms");
                                    pConn_->SetRemoteAddress(remote_addr.IPString(),
                                                             remote_addr.Port());
                                    lastStunTime_ = GetTimeMs();
                                }
                            }
                            else {
                                lastStunTime_ = GetTimeMs();
                            }
                        }
                    }

                    uint8_t trans_id[12];
                    if (stun::GetTransactionID(buffer_, recv_bytes, trans_id)) {
                        Buffer::Ptr sp_resp = GetTlsBuffer(512);
                        sp_resp->setDebugInfo(__FILE__, __LINE__);
                        stun::CreateBindResponse(sp_resp, trans_id, remote_addr, local_pwd);
                        SendData(sp_resp, remote_addr);

                        if (connType_ == CT_DTLS_SERVER) {
                            // also send binding request of our own as well for server
                            string remote_user, remote_pwd;
                            pConn_->GetRemoteIceCredential(remote_user, remote_pwd);

                            // reverse the received id for easier tracking
                            for (int i = 0; i < 6; ++i) {
                                uint8_t tmp = trans_id[i];
                                trans_id[i] = trans_id[11-i];
                                trans_id[11-i] = tmp;
                            }

                            Buffer::Ptr sp_bind = GetTlsBuffer(512);
                            sp_bind->setDebugInfo(__FILE__, __LINE__);
                            stun::CreateBindRequest(sp_bind, remote_user+":"+local_user,
                                                    trans_id, remote_pwd);
                            SendData(sp_bind, remote_addr);
                        }
                    }
                }
                else if (stun::GetMethod(buffer_, recv_bytes) == stun::BINDING) {
                    stun::Type resp_type = stun::GetType(buffer_, recv_bytes);
                    if (resp_type == stun::SUCCESS) {
                        if (!no_stun_log) {
                            MLOG("Stun binding succeeded");
                        }

                        if (connType_ == CT_DTLS_CLIENT && dtlsState_ == INIT) {
                            MLOG("Stun authentication finished");
                            dtlsState_ = HANDSHAKING;
                            SetWriteEvent();
                        }
                    }
                    else if (resp_type == stun::FAILURE) {
                        WLOG("Stun binding failed!");
                    }
                }
                return;
            }

            bool is_tls = (20 <= buffer_[0] && buffer_[0] <= 24);

            if (!is_tls && (buffer_[0] & 0x80)) { // RTP packet
                // encrypt sending buffer using srtp
                int byte_out = recv_bytes;

                uint8_t* p_buf = (uint8_t*)buffer_;

                int paylod_type = p_buf[1] & 0x7f;
                if (paylod_type < 64 ||
                    (96 <= paylod_type && paylod_type <= 127)) {
                    srtp_.Decrypt(p_buf, &byte_out);
                }
                else {
                    srtp_.DecryptRTCP(p_buf, &byte_out);
                }

                DLOG("Decrypt " << recv_bytes << "B -> " << byte_out << "B");

                if (byte_out > 0) {
                    Buffer::Ptr sp_data = pConn_->GetBuffer(byte_out);
                    memcpy(sp_data->getBuf(), p_buf, byte_out);
                    pConn_->OnData(sp_data);
                }
                else {
                    WLOG("failed to decrypt");
                }
            }
            else { // TLS packet
                pDtlsCore_->ProcessData((uint8_t*)buffer_, recv_bytes, TlsCore::PT_DECRYPT);

                switch (dtlsState_)
                {
                case INIT:
                    dtlsState_ = HANDSHAKING;
                    // intentional no break to fall thru to DoDtlsHandshake
                case HANDSHAKING:
                    if (connType_ == CT_DTLS_SERVER) {
                        // check where handshake message is arrived and match the remote
                        // address accordingly otherwise, we may not be able to send handshake
                        // response back to DTLS client
                        Address curr_remote = pConn_->GetRemoteAddress();
                        if (curr_remote != remote_addr) {
                            MLOG("remote address set by handshake request [" << curr_remote <<
                                 " -> " << remote_addr << "]");
                            pConn_->SetRemoteAddress(remote_addr.IPString(), remote_addr.Port());
                        }

                        // Design of openssl on DTLS uses socket directly, however,
                        // fuze transport manages the all socket interface where we don't
                        // separate listen/connected BIOs. Just feed ClientHello with cookie
                        // message one more time and it seems everything is working fine.
                        // If we don't set SSL->d1->listen = 1 then we have retransmission
                        // issue in server side.  Here when listen is set to 0 then we know
                        // ClientHello with Cookie is processed.
                        if (pDtlsCore_->ClientHelloVerified()) {
                            pDtlsCore_->ProcessData((uint8_t*)buffer_,
                                                    recv_bytes,
                                                    TlsCore::PT_DECRYPT);
                        }
                    }
                    // if we are in handshake phase other packets are received
                    // then it unset our timepr in libevent.
                    DoDtlsHandshake();
                    break;
                case ESTABLISHED:
                    // if we are in established state (flight 6 sent) and retransmit of flight 5
                    // comes, this means flight 6 was lost. Send handshake again in this case,
                    // server may not send anything to client
                    if ((*buffer_ == 22) && (connType_ == CT_DTLS_SERVER)) {
                        pDtlsCore_->TriggerHandshake();
                    }
                    break;
                default:;
                }
            }
        }
        else {
            int error = evutil_socket_geterror(socket_);
            if (EVUTIL_ERR_RW_RETRIABLE(error) == false) {
                ELOG(evutil_socket_error_to_string(error));
                event_del(pReadEvent_);
                RemoveWriteEvent();
                EventType type = ET_FAILED;
                if (EVUTIL_ERR_CONNECT_REFUSED(error)) {
                    type = ET_REFUSED;
                }

                pConn_->OnEvent(type);
            }
        }
    } while (recv_bytes > 0);
}

void DtlsTransceiver::OnWriteEvent()
{
    // first check if we are in handshake mode
    if (connType_ == CT_DTLS_CLIENT && dtlsState_ == INIT) {
        // also send binding request of our own as well
        string local_user, local_pwd;
        string remote_user, remote_pwd;
        pConn_->GetLocalIceCredential(local_user, local_pwd);
        pConn_->GetRemoteIceCredential(remote_user, remote_pwd);

        char trans_id[12];
        static int s_id = 100;
        sprintf(trans_id, "%d", s_id++);
        Buffer::Ptr sp_bind = GetTlsBuffer(512);
        stun::CreateBindRequest(sp_bind, remote_user+":"+local_user,
                                (uint8_t*)trans_id, remote_pwd);
        SendData(sp_bind, pConn_->GetRemoteAddress());
        SetReadEvent(200); // keep doing this until we get success response
        RemoveWriteEvent();
    }
    else if (dtlsState_ == HANDSHAKING) {
        DoDtlsHandshake();
    }
    else if (dtlsState_ == ESTABLISHED) {
        // see if we have data to send
        while (true) {
            Buffer::Ptr sp_buf;
            {
                MutexLock scoped(&qLock_);
                if (sendQ_.empty()) {
                    if (writeAdded_ && pWriteEvent_) {
                        event_del(pWriteEvent_);
                        writeAdded_ = false;
                    }
                    break;
                }
                sp_buf = sendQ_.front();
                sendQ_.pop();
            }

            if (sp_buf) {
                EncryptAndSend(sp_buf->getBuf(), sp_buf->size());
            }
        }
    }
}

void DtlsTransceiver::EncryptAndSend(uint8_t* p_buf, uint32_t buf_len)
{
    // encrypt sending buffer using srtp
    uint32_t new_buf_len   = buf_len + SecureRTP::MAX_TRAILER_LEN + 4;
    Buffer::Ptr sp_new_buf = GetTlsBuffer(new_buf_len);

    memcpy(sp_new_buf->getBuf(), p_buf, buf_len);

    // now switch to new buffer
    p_buf = sp_new_buf->getBuf();
    int byte_out = (int)buf_len;

    int paylod_type = p_buf[1] & 0x7f;
    if (paylod_type < 64 ||
        (96 <= paylod_type && paylod_type <= 127)) {
        srtp_.Encrypt(p_buf, &byte_out);
    }
    else {
        srtp_.EncryptRTCP(p_buf, &byte_out);
    }

    DLOG("Encrypt " << buf_len << "B -> " << byte_out << "B");

    if (byte_out == 0) {
        ELOG("failed to encrypt");
    }
    else {
        sp_new_buf->setSize(byte_out);
        SendData(sp_new_buf, pConn_->GetRemoteAddress());
    }
}

void DtlsTransceiver::OnTimeOutEvent()
{
    MLOG("DTLS State: " << StateStr(dtlsState_))

    int32_t timeout = 0;

    if (connType_ == CT_DTLS_CLIENT && dtlsState_ == INIT) {
        // for stun authentication, send another request here
        SetWriteEvent();
    }
    else if (dtlsState_ == HANDSHAKING) {
        // if we are handshaking then we set timeout accordingly
        // if not then we won't have any timer on read event
        if (pDtlsCore_->HandleTimeout()) {
            pDtlsCore_->GetTimeout(timeout);
        }
        else { // error condition
            event_del(pReadEvent_);
            RemoveWriteEvent();
            pConn_->OnEvent(ET_FAILED, "DTLS timer error");
            return;
        }
    }

    SetReadEvent(timeout);
}

void DtlsTransceiver::DoDtlsHandshake()
{
    pDtlsCore_->TriggerHandshake();

    // set read timeout if we need to
    int32_t timeout = 0;

    if (pDtlsCore_->GetTimeout(timeout)) {
        if (timeout == 0) { // expired now
            OnTimeOutEvent();
        }
    }

    // each handshake message may trigger different timeout value
    SetReadEvent(timeout);

    // remove write event as we may have no need to send more now
    RemoveWriteEvent();

    if (pDtlsCore_->IsInHandshake() == false) {
        string profile = pDtlsCore_->GetSelectSrtpProfile();
        MLOG("Selected SRTP profile: " << profile);

        uint8_t dtls_buffer[DtlsCore::SRTP_M_LEN*2];
        pDtlsCore_->GetSrtpKeyMaterial(dtls_buffer);

        SRTP::KeyType key_type = GetSrtpKeyType(profile.c_str());

        uint8_t client_write_key[DtlsCore::SRTP_M_LEN];
        uint8_t server_write_key[DtlsCore::SRTP_M_LEN];

        size_t offset = 0;
        memcpy(&client_write_key[0], &dtls_buffer[offset],
               DtlsCore::SRTP_M_KEY_LEN);
        offset += DtlsCore::SRTP_M_KEY_LEN;
        memcpy(&server_write_key[0], &dtls_buffer[offset],
               DtlsCore::SRTP_M_KEY_LEN);
        offset += DtlsCore::SRTP_M_KEY_LEN;
        memcpy(&client_write_key[DtlsCore::SRTP_M_KEY_LEN],
               &dtls_buffer[offset], DtlsCore::SRTP_M_SALT_LEN);
        offset += DtlsCore::SRTP_M_SALT_LEN;
        memcpy(&server_write_key[DtlsCore::SRTP_M_KEY_LEN],
               &dtls_buffer[offset], DtlsCore::SRTP_M_SALT_LEN);

        if (connType_ == CT_DTLS_SERVER) {
            srtp_.SetSRTPKey(SRTP::SEND, key_type, server_write_key, DtlsCore::SRTP_M_LEN);
            srtp_.SetSRTPKey(SRTP::RECV, key_type, client_write_key, DtlsCore::SRTP_M_LEN);
        } else {
            srtp_.SetSRTPKey(SRTP::RECV, key_type, server_write_key, DtlsCore::SRTP_M_LEN);
            srtp_.SetSRTPKey(SRTP::SEND, key_type, client_write_key, DtlsCore::SRTP_M_LEN);
        }

        dtlsState_ = ESTABLISHED;
        pConn_->OnEvent(ET_CONNECTED, "DTLS handshake finished");
    }
}

void DtlsTransceiver::RemoveWriteEvent()
{
    // due to race condition between app and libevent threads
    // writeAdded/pWriteEvent need to be synchronized by lock
    MutexLock scoped(&qLock_);

    if (writeAdded_ && pWriteEvent_) {
        event_del(pWriteEvent_);
        writeAdded_ = false;
    }
}

const char* DtlsTransceiver::StateStr(DtlsState eState)
{
    switch (eState)
    {
    case INIT:        return "INIT";
    case HANDSHAKING: return "HANDSHAKING";
    case ESTABLISHED: return "ESTABLISHED";
    default:          return "INVALID";
    }
}

} //namespace fuze
