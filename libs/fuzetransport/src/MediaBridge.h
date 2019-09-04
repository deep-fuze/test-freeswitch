//
//  MediaBridge.h
//  FuzeTransport
//
//  Created by Tim Na on 11/12/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#ifndef __MediaBridge_h
#define __MediaBridge_h

#include <TransportImpl.h>

namespace fuze {

class MediaBridge : public ConnectionObserver
{
public:
    MediaBridge();
    virtual ~MediaBridge();

    // Implement ConnectionObserver interface
    virtual void OnDataReceived(void* pContext, Buffer::Ptr spBuffer);
    virtual void OnEvent(void* pContext, EventType eType, const string& rReason);
    
private:
    
    static const uint16_t UDP_PORT = 50000;    
    
    TransportBase::Ptr  spBase_;
    Connection::Ptr     spUdpServer_;
    
    uint32_t            fuzeProbeCnt_;
    uint32_t            fuzeStunCnt_;
};

} // namespace fuze

#endif /* __MediaBridge_h */
