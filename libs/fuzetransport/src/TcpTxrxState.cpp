//
//  TcpTxrxState.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/13/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <TcpTxrxState.h>
#include <TcpTransceiver.h>
#include <ConnectionImpl.h>

#include <Server.h> // for Server::PORT

#include <Mapping.h>
#include <Data.h>

#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_TCP, p->tcpCore_.log_ << __FUZE_FUNC__ << ": " << B)

namespace fuze {
 
const char* toStr(TcpTxrxState::Type type)
{
    switch (type)
    {
    case TcpTxrxState::TCP:            return "StateTCP";
    case TcpTxrxState::TLS:            return "StateTLS";
    case TcpTxrxState::UDP_OVER_TCP:   return "StateUdpOverTCP";
    case TcpTxrxState::DATA_OVER_TLS:  return "StateDataOverTLS";
    case TcpTxrxState::SETUP_TCP:      return "StateSetupTCP";
    case TcpTxrxState::SETUP_TCP_443:  return "StateSetupTcpPort443";
    case TcpTxrxState::SETUP_TLS:      return "StateSetupTLS";
    case TcpTxrxState::SETUP_MAP_TLS:  return "StateSetupMapTLS";
    case TcpTxrxState::SETUP_HTTP:     return "StateSetupHTTP";
    case TcpTxrxState::SETUP_HTTP_TLS: return "StateSetupHTTP&TLS";
    default:                           return "Invalid State";
    }
}

bool is_setup_state(TcpTxrxState::Type type)
{
    switch (type)
    {
        case TcpTxrxState::SETUP_TCP:
        case TcpTxrxState::SETUP_TCP_443:
        case TcpTxrxState::SETUP_HTTP:
        case TcpTxrxState::SETUP_TLS:
        case TcpTxrxState::SETUP_MAP_TLS:
            return true;
        default:
            return false;
    }
}
    
//-----------------------------------------------------------------------------------
// StateTcp
//
//-----------------------------------------------------------------------------------
    
TcpTxrxState* StateTcp::GetInstance()
{
    static StateTcp s_tcp;
    return &s_tcp;
}

void StateTcp::OnConnected(TcpTransceiver* p)
{
    ELOG("Wrong state - StateTcp");
    p->pConn_->OnEvent(ET_FAILED, "Wrong state");
}

uint32_t StateTcp::OnDataReceived(TcpTransceiver* p,
                                  Buffer::Ptr     spBuf)
{
    if (p->bConnected_ == false) {
        ELOG("wrong state machien - StateTcp");
        p->pConn_->OnEvent(ET_FAILED, "Wrong State");
        return 0;
    }
    
    uint32_t read = spBuf->size();
    p->OnDataProcessed(spBuf);
    return read;
}
    
void StateTcp::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    p->tcpCore_.Send(spBuf);
}

//-----------------------------------------------------------------------------------
// StateSetupTcp
//
//-----------------------------------------------------------------------------------

TcpTxrxState* StateSetupTcp::GetInstance()
{
    static StateSetupTcp s_setup_tcp;
    return &s_setup_tcp;
}

void StateSetupTcp::OnConnected(TcpTransceiver* p)
{
    p->bConnected_ = true;
    p->SetState(TCP);
    p->pConn_->OnEvent(ET_CONNECTED, "TCP Connected");
}

uint32_t StateSetupTcp::OnDataReceived(TcpTransceiver* p,
                                       Buffer::Ptr     spBuf)
{
    ELOG("Wrong state - StateSetupTcp");
    p->pConn_->OnEvent(ET_FAILED, "Wrong state");
    return 0;
}

void StateSetupTcp::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    ELOG("wrong state machine - StateSetupTcp");
}
    
//-----------------------------------------------------------------------------------
// StateUdpOverTcp
//
//-----------------------------------------------------------------------------------
    
TcpTxrxState* StateUdpOverTcp::GetInstance()
{
    static StateUdpOverTcp s_udp_over_tcp;
    return &s_udp_over_tcp;
}

void StateUdpOverTcp::OnConnected(TcpTransceiver* p)
{
    ELOG("wrong state machien - StateUdpOverTcp");
    p->pConn_->OnEvent(ET_FAILED, "Wrong state");
}

uint32_t StateUdpOverTcp::OnDataReceived(TcpTransceiver* p,
                                         Buffer::Ptr     spBuf)
{
    if (p->bConnected_ == false) {
        ELOG("wrong state machien - StateUdpOverTcp");
        p->pConn_->OnEvent(ET_FAILED, "Wrong State");
        return 0;
    }
    
    uint8_t* p_buf   = spBuf->getBuf();
    uint32_t buf_len = spBuf->size();
    
    // StateUdpOverTcp only uses Fuze header which requires 1 byte of signature
    msg::Type msg_type = msg::get_type(p_buf, buf_len);
    
    if (msg_type == msg::FUZE) {

        uint32_t msg_len = msg::get_length(p_buf, buf_len);
        
        if (msg_len > 0) {
            // set data size as we know of it now spBuf is created
            // for application that it is safe to set own size
            spBuf->setSize(msg_len);
            
            Data data;
            data.SetAllocator(p->pConn_);
            data.SetReceivedData(spBuf);
            
            // if we are connected then we only have Data to come in
            // add remote address for FreeSwitch
            if (NetworkBuffer* pbuf =
                dynamic_cast<NetworkBuffer*>(data.GetData().get())) {
                p->pConn_->GetOriginalRemoteAddress(pbuf->remoteIP_,
                                                    pbuf->remotePort_);
            }
            
            p->OnDataProcessed(data.GetData());
            
            return msg_len;
        }
        // else not enough so wait for more
    }
    else {
        ELOG("unexpected msg type from far end - StateUdpOverTcp");
        p->pConn_->OnEvent(ET_FAILED, "Unexpected msg on StateUdpOverTcp");
    }
    
    return 0;
}

void StateUdpOverTcp::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    fuze::Data data;
    data.SetAllocator(p->pConn_);
    data.SetDataToSend(spBuf);
    
    if (Buffer::Ptr sp_header = data.GetHeader()) {
        p->tcpCore_.Send(sp_header);
    }
    
    if (Buffer::Ptr sp_data = data.GetData()) {
        p->tcpCore_.Send(sp_data);
    }
}
    
//-----------------------------------------------------------------------------------
// StateSetupTcpPort443
//
//-----------------------------------------------------------------------------------
    
TcpTxrxState* StateSetupTcpPort443::GetInstance()
{
    static StateSetupTcpPort443 s_setup_tcp;
    return &s_setup_tcp;
}
    
void StateSetupTcpPort443::OnConnected(TcpTransceiver* p)
{
    if (p->bConnected_ == false) {
        Buffer::Ptr sp_map = p->MakeMapRequest();
        MLOG("Sending Mapping request\n" << (char*)sp_map->getBuf());
        p->tcpCore_.Send(sp_map);
    }
    else {
        ELOG("wrong state - StateSetupTcpPort443");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
    }
}

uint32_t StateSetupTcpPort443::OnDataReceived(TcpTransceiver* p,
                                              Buffer::Ptr     spBuf)
{
    if (p->bConnected_) {
        ELOG("wrong state machine - StateSetupTcpPort443");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
        return 0;
    }
    
    return p->OnMapResponse(spBuf);
}

void StateSetupTcpPort443::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    ELOG("wrong state machine - StateSetupTcpPort443");
}

//-----------------------------------------------------------------------------------
// StateSetupTls
//
//-----------------------------------------------------------------------------------
    
TcpTxrxState* StateSetupTls::GetInstance()
{
    static StateSetupTls s_setup_tls;
    return &s_setup_tls;
}

void StateSetupTls::OnConnected(TcpTransceiver* p)
{
    if (p->bConnected_ == false) {
        // first create TLS core and start handshake
        p->spTlsCore_.reset(new TlsCore(*p));
        
        // copy the debug info
        strncpy(p->spTlsCore_->log_, p->tcpCore_.log_, 64);

        p->spTlsCore_->Init();
        p->spTlsCore_->TriggerHandshake();
    }
    else {
        ELOG("wrong state machine - StateSetupTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
    }
}

uint32_t StateSetupTls::OnDataReceived(TcpTransceiver* p,
                                       Buffer::Ptr     spBuf)
{
    // we are expecting TLS message back
    if (p->bConnected_) {
        ELOG("wrong state machine - StateSetupTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
        return 0;
    }
    
    uint32_t read = p->spTlsCore_->ProcessData(spBuf->getBuf(),
                                               spBuf->size(),
                                               TlsCore::PT_DECRYPT);
    if (p->spTlsCore_->IsInHandshake()) {
        p->spTlsCore_->TriggerHandshake();
    }
    else {
        
        // in some corner case, tcp transceiver is already cleaned up
        // after handshake failure in the end MQT-6339
        if (!p->pConn_) return read;
        
        ConnectionType orig = p->pConn_->GetOriginalConnectionType();
        
        MLOG("TLS handshake is done [" << p->spTlsCore_->GetVersion() <<
             "] (requested connection: " << toStr(orig) << ")");
        
        // if application has requested TLS connection then far end
        // must be TLS endpoint - expecting full TLS stuff
        if (orig == CT_TLS) {
            p->bConnected_ = true;
            p->SetState(TLS);
            p->pConn_->OnEvent(ET_CONNECTED, "TLS Connected");
        }
        else {
            // now go to next state to query whether
            // this is FuzeTransport or not
            p->SetState(SETUP_MAP_TLS);
            p->pState_->OnConnected(p);
        }
    }
    
    return read;
}

void StateSetupTls::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    ELOG("wrong state machine - StateSetupTls");
}

//-----------------------------------------------------------------------------------
// StateSetupMapTls
//
//-----------------------------------------------------------------------------------

TcpTxrxState* StateSetupMapTls::GetInstance()
{
    static StateSetupMapTls s_setup_tls;
    return &s_setup_tls;
}

void StateSetupMapTls::OnConnected(TcpTransceiver* p)
{
    if (p->bConnected_ == false) {
        Buffer::Ptr sp_map = p->MakeMapRequest();
        MLOG("Sending Mapping request over TLS\n--------------------\nSEND:\n\n" <<
             (char*)sp_map->getBuf() << "--------------------");
        p->spTlsCore_->ProcessData(sp_map->getBuf(),
                                   sp_map->size(),
                                   TlsCore::PT_ENCRYPT);
    }
    else {
        ELOG("wrong state - StateSetupMapTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
    }
}

uint32_t StateSetupMapTls::OnDataReceived(TcpTransceiver* p,
                                          Buffer::Ptr     spBuf)
{
    if (p->bConnected_) {
        ELOG("wrong state machine - StateSetupMapTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
        return 0;
    }
    
    // if we have TLS connecion then we would receive TLS response
    return p->spTlsCore_->ProcessData(spBuf->getBuf(),
                                      spBuf->size(),
                                      TlsCore::PT_DECRYPT);
}

void StateSetupMapTls::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    ELOG("wrong state machine - StateSetupMapTls");
}
    
//-----------------------------------------------------------------------------------
// StateDataOverTls
//
//-----------------------------------------------------------------------------------
    
TcpTxrxState* StateDataOverTls::GetInstance()
{
    static StateDataOverTls s_data_tls;
    return &s_data_tls;
}

void StateDataOverTls::OnConnected(TcpTransceiver* p)
{
    ELOG("wrong state machine - StateDataOverTls");
    p->pConn_->OnEvent(ET_FAILED, "Wrong state");
}

uint32_t StateDataOverTls::OnDataReceived(TcpTransceiver* p,
                                          Buffer::Ptr     spBuf)
{
    // we are expecting TLS message back
    if (p->bConnected_ == false) {
        ELOG("wrong state machine - StateDataOverTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
        return spBuf->size();
    }
    
    uint32_t data_read = 0;
    
    uint8_t* p_buf = spBuf->getBuf();
    uint32_t buf_len = spBuf->size();
    
    if (msg::is_tls(*p_buf)) {
        uint32_t tls_len = msg::get_length(p_buf, buf_len);
        
        if (tls_len == 0) {
            DLOG("Wait for more TLS data - current " << buf_len << "B");
            return 0;
        }
        
        // set data size as we know of it now
        spBuf->setSize(tls_len);
        
        TlsAppData tls_data;
        tls_data.SetAllocator(p->pConn_);
        tls_data.SetReceivedData(spBuf);
        
        if (NetworkBuffer* pbuf =
                dynamic_cast<NetworkBuffer*>(tls_data.GetData().get())) {
            p->pConn_->GetOriginalRemoteAddress(pbuf->remoteIP_,
                                                pbuf->remotePort_);
        }
        
        p->OnDataProcessed(tls_data.GetData());
        
        data_read = tls_len;
    }
    else {
        ELOG("unexpected message received - StateDataOverTls");
        p->pConn_->OnEvent(ET_FAILED, "unexpected msg on StateDataOverTls");
        // discard the data as if we consumed it
        data_read = buf_len;
        WLOG("Data " << buf_len << "B [" << Hex(p_buf) << "]");
    }
    
    return data_read;
}

void StateDataOverTls::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    TlsAppData tls_data;
    tls_data.SetAllocator(p->pConn_);
    tls_data.SetDataToSend(spBuf);
    
    if (Buffer::Ptr sp_header = tls_data.GetHeader()) {
        p->tcpCore_.Send(sp_header);
    }
    
    if (Buffer::Ptr sp_data = tls_data.GetData()) {
        p->tcpCore_.Send(tls_data.GetData());
    }
}

//-----------------------------------------------------------------------------------
// StateTls
//
//-----------------------------------------------------------------------------------

TcpTxrxState* StateTls::GetInstance()
{
    static StateTls s_tls;
    return &s_tls;
}

void StateTls::OnConnected(TcpTransceiver* p)
{
    ELOG("wrong state machine - StateTls");
    p->pConn_->OnEvent(ET_FAILED, "Wrong state");
}

uint32_t StateTls::OnDataReceived(TcpTransceiver* p,
                                  Buffer::Ptr     spBuf)
{
    // we are expecting TLS message back
    if (p->bConnected_ == false) {
        ELOG("wrong state machine - StateTls");
        p->pConn_->OnEvent(ET_FAILED, "Wrong state");
        return 0;
    }
    
    if (!p->spTlsCore_) {
        ELOG("TlsCore is not available");
        p->pConn_->OnEvent(ET_FAILED, "TlsCore not available");
        return 0;
    }
    
    return p->spTlsCore_->ProcessData(spBuf->getBuf(),
                                      spBuf->size(),
                                      TlsCore::PT_DECRYPT);
}

void StateTls::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    if (!p->spTlsCore_) {
        ELOG("TlsCore is not available");
        p->pConn_->OnEvent(ET_FAILED, "TlsCore not available");
        return;
    }
    
    p->spTlsCore_->ProcessData(spBuf->getBuf(),
                               spBuf->size(),
                               TlsCore::PT_ENCRYPT);
}

//-----------------------------------------------------------------------------------
// StateHttpTls
//
//-----------------------------------------------------------------------------------

TcpTxrxState* StateHttpTls::GetInstance()
{
    static StateTls s_tls;
    return &s_tls;
}

void StateHttpTls::OnConnected(TcpTransceiver* p)
{
    ELOG("wrong state machine - StateHttpTls");
}

uint32_t StateHttpTls::OnDataReceived(TcpTransceiver* p,
                                      Buffer::Ptr     spBuf)
{
    ELOG("wrong state machine - StateHttpTls");    
    return 0;
}

void StateHttpTls::Send(TcpTransceiver* p, Buffer::Ptr spBuf)
{
    ELOG("wrong state machine - StateHttpTls");
}
    
} // namespace fuze
