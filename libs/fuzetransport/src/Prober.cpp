//
//  Prober.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/2/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Prober.h>
#include <Stun.h>
#include <Log.h>

#ifdef __ANDROID_API__
#include <netinet/in.h>
#endif

#ifdef __linux__
#include <string.h>
#endif

#ifdef WIN32
#include <ws2tcpip.h>
#endif

#ifdef WIN32
#define FNAME ""
#else
#define FNAME "Prober::"
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, FNAME << __FUZE_FUNC__ << ": " << B)

#define USE_STUN

namespace fuze {

Prober::Prober()
    : probing_(false)
    , udpBlocked_(false)
    , startTime_(0)
    , handle_(0)
{
}

bool Prober::IsUdpBlocked()
{
    return udpBlocked_;
}

void Prober::StartUdpProbe(const string& rAddr, uint16_t port)
{
    if (probing_) {
        ELOG("Probing in process");
        return;
    }

    string remote_ip = TranslateToIP(rAddr);
    if (remote_ip.empty()) { // DNS fails then we can't do this
        ELOG("DNS query failed for prober");
        return;
    }
    
    probing_    = true;
    udpBlocked_ = false;
    
    spBase_ = Transport::GetInstance()->CreateBase("prob");
    spConn_ = spBase_->CreateConnection("prob");
            
    spConn_->RegisterObserver(this);
    
    if (spConn_->SetRemoteAddress(remote_ip, port)) {
        // UDP should be setup right away
        if (spConn_->Start(CT_UDP, Connection::NO_FALLBACK)) {
#ifndef USE_STUN
            const char* p = "FUZEPROBE"  // prefix
                            "        1"  // version
                            "RQST";      // request
            int len = (int)strlen(p);
            const int REQ_LEN = 160;
            
            spReq_ = spConn_->GetBuffer(REQ_LEN);
            spReq_->setDebugInfo(__FILE__, __LINE__);
            uint8_t* p_buf = spReq_->getBuf();
            memset(p_buf, '.', REQ_LEN);
            memcpy(p_buf, p, len);
            spReq_->setSize(REQ_LEN);
#else
            uint8_t trans_id[12] = {0};
            spReq_ = spConn_->GetBuffer(512);
            spReq_->setDebugInfo(__FILE__, __LINE__);
            // also send binding request of our own as well for server
            stun::CreateBindRequest(spReq_, "FuzeServer:FuzeClient",
                                    trans_id, "", true);
#endif
            MutexLock scoped(&lock_);
            spConn_->Send(spReq_);
            startTime_ = GetTimeMs();
            handle_    = StartTimer(this, 300, 0);
            MLOG("Starting timer handle " << handle_);
        }
        else {
            ELOG("Failed to setup UDP for prober");
            Reset();
        }
    }
    else {
        Reset();
    }
}

void Prober::Reset()
{
    if (handle_) {
        MLOG("Stopping timer handle " << handle_);
        StopTimer(this, handle_);
        handle_ = 0;
    }
    
    spReq_.reset();
    spConn_.reset();
    spBase_.reset();
    
    probing_ = false;
}
    
void Prober::OnDataReceived(void* pContext, Buffer::Ptr spBuffer)
{
    MLOG("Probe response came - UDP not blocked");
    
#ifdef USE_STUN
    char*    p_buf   = (char*)spBuffer->getBuf();
    uint32_t buf_len = spBuffer->size();
    
    if (stun::IsStun(p_buf, buf_len)) {
        // for logging as we print while validating
        stun::Validate(p_buf, buf_len, "", false);
    }
#endif
    
    MutexLock scoped(&lock_);
    udpBlocked_ = false;
    Reset();
}

void Prober::OnEvent(void* pContext, EventType eType, const string& rReason)
{
    MLOG(toStr(eType) << " (" << rReason << ")");

    if (eType == ET_REFUSED || eType == ET_FAILED) {
        MLOG("Probing timeout - UDP looks to be blocked");
        MutexLock scoped(&lock_);
        udpBlocked_ = true;
        Reset();
    }
}

void Prober::OnTimer(int32_t appData)
{
    int64_t time_passed = GetTimeMs() - startTime_;
    
    {
        MutexLock scoped(&lock_);
        
        if (!probing_) return;
        
        handle_ = 0;
        
        if (time_passed < 5000) {
            spConn_->Send(spReq_);
            handle_ = StartTimer(this, 100, 0);
        }
    }

    // spConn_.reset() can cause deadlock with transport thread
    // lock_ will control the critical sections for probing & handle_
    if (time_passed >= 5000) {
        MLOG("Probing timeout - UDP looks to be blocked");
        udpBlocked_ = true;
        Reset();
    }
}
    
} // namespace fuze
