//
//  ServerCore.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/29/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <ServerCore.h>
#include <Server.h>
#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <TcpTransceiver.h>
#include <ResourceMgr.h>
#include <Mapping.h>

#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, tcpCore_.log_ << __FUZE_FUNC__ << ": " << B)

namespace fuze {

BindingInfo::BindingInfo()
{
    Clear();
}

void BindingInfo::Clear()
{
    type_   = CT_INVALID;
    connID_ = INVALID_ID;
    ipStr_.clear();
    port_   = 0;
}

ServerCore::ServerCore(int ID)
    : Resource(ID)
    , tcpCore_(*this)
    , socket_(INVALID_SOCKET)
    , pState_(StateInitial::GetInstance())
{
}

void ServerCore::Reset()
{
    if (IsActive() == true) {
        MLOG("ACTIVE -> ZOMBIE");
        SetZombie();
        tcpCore_.Reset();

        spTlsCore_.reset();
        recvBuf_.reset();

        pState_ = StateInitial::GetInstance();

        if (socket_ != INVALID_SOCKET) {
            evutil_closesocket(socket_);
        }
        socket_ = INVALID_SOCKET;

        bindInfo_.Clear();

        startTime_ = 0;
    }
}

void ServerCore::SetSocket(evutil_socket_t sock)
{
    DLOG("ServerCore socket set to " << sock);

    socket_ = sock;

    // remove relevant libevent as we won't be
    // interested in those anymore
    if (tcpCore_.pReadEvent_) {
        event_free(tcpCore_.pReadEvent_);
        tcpCore_.pReadEvent_ = 0;
    }

    if (tcpCore_.pWriteEvent_) {
        event_free(tcpCore_.pWriteEvent_);
        tcpCore_.pWriteEvent_ = 0;
    }

    if (socket_ != INVALID_SOCKET) {
        sprintf(tcpCore_.log_ , "FwCore[co%d:s%d] ", ID(), socket_);
        tcpCore_.StartReceive();
    }
}

void ServerCore::SendHttpResponse(uint32_t code, const char* pReason)
{
    tp::HttpResponse rsp;
    rsp.SetResponseLine(code, pReason);

    Buffer::Ptr sp_out = rsp.Serialize();
    MLOG("\n--------------------\nSEND:\n\n" <<
         (char*)sp_out->getBuf() << "--------------------");

    if (spTlsCore_) {
        spTlsCore_->ProcessData(sp_out->getBuf(),
                                sp_out->size(),
                                TlsCore::PT_ENCRYPT);
    }
    else {
        tcpCore_.Send(sp_out);
    }

}

uint32_t ServerCore::OnDataReceived(Buffer::Ptr spBuf)
{
    return pState_->OnDataReceived(this, spBuf);
}

void ServerCore::OnBytesSent(uint32_t bytesSent)
{
    // process when everything is sent over
    size_t q_size = 0;
    uint32_t q_buf_size = 0;
    tcpCore_.GetSendQInfo(q_size, q_buf_size);
    if (q_size != 0) {
        return;
    }

    // if we sent an error response in failed state
    // then we are done.
    if (pState_->GetType() == CoreState::FAILED) {
        RequestRemove();
        return;
    }

    // use bindInfo_'s connID_ as condition to trigger
    // if we have found right connection to bind the connection
    if (bindInfo_.connID_ == INVALID_ID) {
        return;
    }

    ConnectionImpl* p_con =
        ResourceMgr::GetInstance()->GetConnection(bindInfo_.connID_);

    if (!p_con) {
        ELOG("Connection [c" << bindInfo_.connID_ << "] is not active");
        RequestRemove();
        return;
    }

    switch (bindInfo_.type_)
    {
    case CT_UDP:
    case CT_BULK_UDP:
        // map this client to corresponding connection object
        if (Transceiver* p =
                ResourceMgr::GetInstance()->GetNewTransceiver(CT_TCP)) {
            // set connection binding
            p->SetConnectionID(bindInfo_.connID_);
            if (TcpTransceiver* p_tcp =
                dynamic_cast<TcpTransceiver*>(p)) {
                // Transfer the socket from ServerCore
                evutil_socket_t sock = socket_;
                SetSocket(INVALID_SOCKET);
                RequestRemove();

                if (pState_->GetType() == CoreState::INITIAL) {
                    // mark this as UDP over TCP type
                    p_tcp->SetState(TcpTxrxState::UDP_OVER_TCP);
                }
                else {
                    p_tcp->SetState(TcpTxrxState::DATA_OVER_TLS);
                }

                if (p_tcp->Start(sock)) {
                    p_con->ReplaceTransceiver(p_tcp);
                }
            }
        }
        else {
            ELOG("Failed to get a new TCP Transceiver");
        }
        break;
    case CT_TCP_LISTENER:
    {
        // find corresponding base and invoke base API
        int base_id = p_con->BaseID();
        if (TransportBaseImpl* p =
                ResourceMgr::GetInstance()->GetBase(base_id)) {
            // transfer the socket from ServerCore to base API
            evutil_socket_t sock = socket_;
            SetSocket(INVALID_SOCKET);
            bool is_tls = false;
            if (pState_->GetType() == CoreState::ACCEPTED_TLS) {
                is_tls = true;
            }
            p->AddNewConnection(sock, is_tls);
            RequestRemove();
        }
        else {
            ELOG("Base [b" << base_id << "] is not active");
        }
        break;
    }
    default:
        ELOG("invalid connection type");
    }
}

void ServerCore::OnBytesRecv(uint32_t bytesRecv)
{

}

evutil_socket_t ServerCore::Socket()
{
    return socket_;
}

void ServerCore::OnDisconnect()
{
    MLOG("Far end closed the connection");

    RequestRemove();
}

void ServerCore::OnReadError(int error)
{
    RequestRemove();
}

void ServerCore::OnWriteError(int error)
{
    RequestRemove();
}

void ServerCore::OnDataEncrypted(Buffer::Ptr spData)
{
    MLOG("Sending encrypted data " << spData->size() << "B");
    tcpCore_.Send(spData);
}

void ServerCore::OnDataDecrypted(Buffer::Ptr spData)
{
    // we only expect HTTP POST request here
    if (!recvBuf_) {
        recvBuf_ = spData;
    }
    else {
        uint8_t* p_data   = spData->getBuf();
        uint32_t data_len = spData->size();
        uint8_t* p_buf    = recvBuf_->getBuf();
        uint32_t buf_len  = recvBuf_->size();
        Buffer::Ptr new_buf = Buffer::MAKE(data_len+buf_len+1);
        uint8_t* p_new = new_buf->getBuf();
        memcpy(p_new, p_buf, buf_len);
        memcpy(p_new+buf_len, p_data, data_len);
        p_new[buf_len+data_len] = 0;
        new_buf->setSize(data_len+buf_len);
        recvBuf_ = new_buf;
    }

    // now parse received message
    uint8_t* p_msg   = recvBuf_->getBuf();
    uint32_t msg_len = recvBuf_->size();

    msg::Type msg_type = msg::get_type(p_msg, msg_len);

    MLOG("Received " << toStr(msg_type));

    if (msg_type == msg::HTTP) {
        OnHttpMessage(p_msg, msg_len);
    }
    else if (msg_len > 10) {
        ELOG("Unexpected connection");
        RequestRemove();
    }
}

void ServerCore::OnInternalError()
{
    RequestRemove();
}

Buffer::Ptr ServerCore::GetBuffer(uint32_t bufSize)
{
    return Buffer::MAKE(bufSize);
}

Buffer::Ptr ServerCore::GetBuffer(Buffer::Ptr spBuf)
{
    return Buffer::makeShallowCopy(spBuf);
}

Buffer::Ptr ServerCore::GetTlsBuffer(uint32_t bufSize)
{
    return Buffer::MAKE(bufSize);
}

uint32_t ServerCore::OnHttpMessage(uint8_t* pBuf, uint32_t bufLen)
{
    using tp::HttpRequest;

    uint32_t msg_len = msg::get_length(pBuf, bufLen);
    if (msg_len == 0) {
        return 0;
    }

    if (msg::is_http_response(pBuf, bufLen)) {
        ELOG("Unexpected HTTP response:\n" << (char*)pBuf);
        return bufLen;
    }

    HttpRequest::Type type = HttpRequest::ParseMethodType((char*)pBuf, bufLen);

    if (type == HttpRequest::CONNECT) {
        SendHttpResponse(200, "OK");
    }
    else if (type == HttpRequest::POST) {

        HttpRequest req;
        req.Parse(pBuf, bufLen);

        Mapping* p_map = 0;

        if (MsgBody::Ptr sp_body = req.GetMsgBody()) {
            if (sp_body->GetType() == MsgBody::MAP) {
                p_map = dynamic_cast<Mapping*>(sp_body.get());
            }
        }

        if (!p_map) {
            SendHttpResponse(404, "Not Found");
            return msg_len;
        }

        if (Server::Ptr sp_server =
                TransportImpl::GetInstance()->GetServer()) {
            // if mapping succeeds, we are going to send
            // response back using newly create TcpTransceiver
            // and ServerCore will be set to invalid.
            if (sp_server->GetBindingInfo(bindInfo_, *p_map)) {
                SendHttpResponse(200, "OK");
            }
            else {
                ELOG("Failed to binding info [" <<
                     toStr(p_map->ConnType()) <<
                     "] " << p_map->IP() << ":" <<
                     p_map->Port() << " in server");

                SendHttpResponse(406, "Not Acceptable");
                SetState(CoreState::FAILED);
            }
        }
        else {
            SendHttpResponse(500, "Internal Server Error");
            SetState(CoreState::FAILED);
        }
    }
    else {
        SendHttpResponse(405, "Method Not Allowed");
    }

    return msg_len;
}

void ServerCore::RequestRemove()
{
    if (Server::Ptr p = TransportImpl::GetInstance()->GetServer()) {
        p->RemoveServerCore(ID());
    }
}

void ServerCore::SetState(CoreState::Type type)
{
    MLOG(toStr(pState_->GetType()) << " -> " << toStr(type));

    switch (type)
    {
    case CoreState::INITIAL:
        pState_ = StateInitial::GetInstance();
        break;
    case CoreState::ACCEPT_TLS:
        pState_ = StateAcceptTls::GetInstance();
        break;
    case CoreState::ACCEPTED_TLS:
        pState_ = StateAcceptedTls::GetInstance();
        break;
    case CoreState::FAILED:
        pState_ = StateFailed::GetInstance();
        break;
    }
}

void ServerCore::SetStartTime()
{
    startTime_ = GetTimeMs();
}

int64_t ServerCore::GetStartTime()
{
    return startTime_;
}

} // namespace fuze
