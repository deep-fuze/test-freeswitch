//
//  CoreState.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/26/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Server.h>
#include <CoreState.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, p->tcpCore_.log_ << __FUZE_FUNC__ << ": " << B)

namespace fuze {

const char* toStr(CoreState::Type type)
{
    switch (type)
    {
    case CoreState::INITIAL:      return "StateInitial";
    case CoreState::ACCEPT_TLS:   return "StateAcceptTLS";
    case CoreState::ACCEPTED_TLS: return "StateAcceptedTLS";
    case CoreState::FAILED:       return "StateFailed";
    default:                      return "StateInvalid";
    }
}

//-----------------------------------------------------------------------------------
// StateInitial
//
//-----------------------------------------------------------------------------------
    
CoreState* StateInitial::GetInstance()
{
    static StateInitial s_initial;
    return &s_initial;
}
    
uint32_t StateInitial::OnDataReceived(ServerCore* p,
                                      Buffer::Ptr spBuf)
{
    uint32_t msg_len = 0;
    
    // At initial state, we have following cases from client
    //
    //  1. Mapping request
    //  2. TLS request
    //  3. HTTP CONNECT
    //
    uint8_t* p_buf   = spBuf->getBuf();
    uint32_t buf_len = spBuf->size();
    
    msg::Type msg_type = msg::get_type(p_buf, buf_len);
                                          
    switch (msg_type)
    {
    case msg::HTTP:
        msg_len = p->OnHttpMessage(p_buf, buf_len);
        break;
    case msg::TLS:
        p->spTlsCore_.reset(new TlsCore(*p, true));
        p->spTlsCore_->Init();
        p->SetState(CoreState::ACCEPT_TLS);            
        msg_len = p->pState_->OnDataReceived(p, spBuf);
        break;
    case msg::FUZE:
        ELOG("Wrong message for this state - StateInitial");
        msg_len = buf_len; // mark it as read
        break;
    default:;
        ELOG("Invalid message received");
        msg_len = buf_len; // mark it as read
    }
    
    return msg_len;
}

//-----------------------------------------------------------------------------------
// StateAcceptTls
//
//-----------------------------------------------------------------------------------
    
CoreState* StateAcceptTls::GetInstance()
{
    static StateAcceptTls s_accept_tls;
    return &s_accept_tls;
}
    
uint32_t StateAcceptTls::OnDataReceived(ServerCore* p,
                                        Buffer::Ptr spBuf)
{
    uint32_t read = p->spTlsCore_->ProcessData(spBuf->getBuf(),
                                               spBuf->size(),
                                               TlsCore::PT_DECRYPT);
    if (p->spTlsCore_->IsInHandshake()) {
        p->spTlsCore_->TriggerHandshake();
    }
    else {
        MLOG("handshake finished with client: " << p->spTlsCore_->GetVersion());
        p->spTlsCore_->TriggerHandshake();
        p->SetState(ACCEPTED_TLS);
    }
    
    return read;
}

//-----------------------------------------------------------------------------------
// StateAcceptedTls
//
//-----------------------------------------------------------------------------------

CoreState* StateAcceptedTls::GetInstance()
{
    static StateAcceptedTls s_accepted_tls;
    return &s_accepted_tls;
}

uint32_t StateAcceptedTls::OnDataReceived(ServerCore* p,
                                          Buffer::Ptr spBuf)
{
    uint32_t read = p->spTlsCore_->ProcessData(spBuf->getBuf(),
                                               spBuf->size(),
                                               TlsCore::PT_DECRYPT);
    return read;
}
    
//-----------------------------------------------------------------------------------
// StateFailed
//
//-----------------------------------------------------------------------------------
    
CoreState* StateFailed::GetInstance()
{
    static StateFailed s_failed;
    return &s_failed;
}

uint32_t StateFailed::OnDataReceived(ServerCore* p,
                                     Buffer::Ptr spBuf)
{
    ELOG("StateFailed");
    return 0;
}

} // namespace fuze
