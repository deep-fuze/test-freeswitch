//
//  Prober.h
//  FuzeTransport
//
//  Created by Tim Na on 1/2/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__Prober__
#define __FuzeTransport__Prober__

#include <Transport.h>
#include <MutexLock.h>

namespace fuze {

class Prober : public ConnectionObserver
             , public Timer
{
public:
    typedef fuze_shared_ptr<Prober> Ptr;
    
    Prober();
    
    bool IsUdpBlocked();
    void StartUdpProbe(const string& rAddr, uint16_t port);
    void Reset();
    
private:
    // ConnectionObserver interface
    virtual void OnDataReceived(void*       pContext,
                                Buffer::Ptr spBuffer);
    virtual void OnEvent(void*         pContext,
                         EventType     eType,
                         const string& rReason);
    
    // Timer interface
    virtual void OnTimer(int32_t appData);
    
private:
    
    bool                probing_;
    bool                udpBlocked_;
    
    TransportBase::Ptr  spBase_;
    Connection::Ptr     spConn_;
    Buffer::Ptr         spReq_;
    
    int64_t             startTime_;
    int64_t             handle_;
    
    MutexLock           lock_; // sync between timer and libevent
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__Prober__) */
