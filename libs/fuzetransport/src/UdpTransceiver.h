//
//  UdpTransceiver.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FUZE_UDP_TRANSCEIVER_H__
#define __FUZE_UDP_TRANSCEIVER_H__

#include <Transceiver.h>

namespace fuze {
    
class UdpTransceiver : public Transceiver
{
public:
    explicit UdpTransceiver(int transID);

    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const unsigned char* buf, size_t size);
    virtual void SetConnectionID(int connID);
    virtual ConnectionType ConnType();

    // Implement Resource Interface
    virtual void Reset();
    
private:
    
    bool CreateLibEvent(uint16_t timeout);
    
    bool HandleRemoteChange(const Address& rRecvAddr);
    
    // Interface for libevent callback
    static void OnLibEvent(evutil_socket_t sock, short what, void* pArg);
    void OnReadEvent();
    void OnWriteEvent();
    void OnTimeOutEvent();
    void onWriteEventInternal(char* p_buf, long  size, Buffer::Ptr sp_buf);
    
    int                 connID_;
    ConnectionImpl*     pConn_;
    
    evutil_socket_t     socket_;
    
    event*              pReadEvent_;
    event*              pWriteEvent_;
    
    bool                connectedUdp_;
    string              remoteIP_;
    uint16_t            remotePort_;

    bool                bConnected_;      // flag to track first packet came in
    
    MutexLock           qlock_;
    queue<Buffer::Ptr>  sendQ_;
    bool                writeAdded_;
    
    bool                reservedPort_;    // for NGV, reserving port

    uint32_t            recvBufSize_;
    
private: // NAT adopatation logic
    uint64_t            recvCnt_;         // valid stream count
    int64_t             checkTime_;
    uint64_t            lastRecvCnt_;
    uint16_t            remoteChangeCnt_; // counter to monitor remote change
    Address             lastNewRemoteAddr_;

    char                pName_[16];
    
};
    
} // namespace fuze


#endif
