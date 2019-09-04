//
//  MediaBridge.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/12/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#include "MediaBridge.h"
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

MediaBridge::MediaBridge()
    : fuzeProbeCnt_(0)
    , fuzeStunCnt_(0)
{
    spBase_ = Transport::GetInstance()->CreateBase("MediaBridge");
    
    spUdpServer_ = spBase_->CreateConnection("UdpServer");
    spUdpServer_->RegisterObserver(this);
    spUdpServer_->SetLocalAddress("0.0.0.0", UDP_PORT);
    spUdpServer_->SetRemoteAddressPerBuffer(true);
    if (spUdpServer_->Start(CT_UDP, Connection::NO_FALLBACK) == false) {
        ELOG("Failed to start UDP Server");
        exit(1);
    }
}

MediaBridge::~MediaBridge()
{
    spUdpServer_.reset();
    spBase_.reset();
}

void MediaBridge::OnDataReceived(void* pContext, Buffer::Ptr spBuffer)
{
    char*    p_buf   = (char*)spBuffer->getBuf();
    uint32_t buf_len = spBuffer->size();
    
    if (memcmp(p_buf, "FUZEPROBE", 9) == 0) {
        fuzeProbeCnt_++;
        p_buf += 18;
        if (memcmp(p_buf, "RQST", 4) == 0) {
            memcpy(p_buf, "RESP", 4);
            spUdpServer_->Send(spBuffer);
        }
    }
    else if (stun::IsStun(p_buf, buf_len)) {
        if (stun::GetType(p_buf, buf_len) == stun::REQUEST &&
            stun::GetMethod(p_buf, buf_len) == stun::BINDING) {
            static string s_no_pwd; // avoid meaningless copy
            //stun::Validate(p_buf, buf_len, s_no_pwd, false); // for logging
            fuzeStunCnt_++;
            uint8_t tx_id[12];
            if (stun::GetTransactionID(p_buf, buf_len, tx_id)) {
                Address addr;
                if (NetworkBuffer::Ptr sp_net =
                    fuze_dynamic_pointer_cast<NetworkBuffer>(spBuffer)) {
                    addr.SetIP(sp_net->remoteIP_.c_str());
                    addr.SetPort(sp_net->remotePort_);
                    if (NetworkBuffer::Ptr sp_resp =
                        stun::CreateBindResponse(tx_id, addr, s_no_pwd)) {
                        sp_resp->remoteIP_   = sp_net->remoteIP_;
                        sp_resp->remotePort_ = sp_net->remotePort_;
                        spUdpServer_->Send(sp_resp);
                    }
                }
            }
        }
    }
    
    // print every 100th for logging purpose
    if (((fuzeProbeCnt_ + fuzeStunCnt_) % 500) == 0) {
        MLOG("Fuze Probe: " << fuzeProbeCnt_ << " Stun: " << fuzeStunCnt_);
    }
}
    
void MediaBridge::OnEvent(void* pContext, EventType eType, const string& rReason)
{
    
}

} // namespace fuze
