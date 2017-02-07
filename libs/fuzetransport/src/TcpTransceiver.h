//
//  TcpTransceiver.h
//  FuzeTransport
//
//  Created by Tim Na on 11/20/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TcpTransceiver__
#define __FuzeTransport__TcpTransceiver__

#include <Transceiver.h>
#include <TcpCore.h>
#include <TlsCore.h>
#include <TcpTxrxState.h>
#include <ProxyConnector.h>

#include <queue>
#include <memory>

namespace fuze {

using std::queue;
using std::auto_ptr;

//
// TcpFramer handles fragment/defragment of
// Tcp data on behalf of application
//
class TcpFramer
{
public:
    TcpFramer(TcpCoreUser& rUser);

    void SetMTU(uint32_t mtu);
    void Clear();
    
    void SetSendData(Buffer::Ptr spBuf);
    bool GetSendFrame(Buffer::Ptr& rspBuf);
    
    void SetRecvFrame(Buffer::Ptr spBuf);
    bool GetRecvData(Buffer::Ptr& rspBuf,
                     uint8_t&     rHeadType);

    void SetDebugLog(const char* p);
    
    static const uint8_t  DATA_HEAD   = 0;
    static const uint8_t  RATE_HEAD   = 1;
    static const uint8_t  MAP_HEAD    = 2;
    static const uint32_t HEADER_SIZE = 6;
    
private:
    
    Buffer::Ptr  spSendHeader_;
    Buffer::Ptr  spSendBuffer_;
    uint32_t     MTU_; // if DataOverTls is used then Max
                       // Transmit Unit is 18000 bytes
    Buffer::Ptr  spRecvBuffer_; // hold incoming data for WYSWYG
    uint32_t     recvSize_;
    uint32_t     recvBytes_;
    uint8_t      headType_;
    
    TcpCoreUser& rCoreUser_; // to get buffer from
    
    char         log_[64]; // debug purpose
};
    
class TcpTransceiver : public Transceiver
                     , public TcpCoreUser
                     , public TlsCoreUser
{
public:
    explicit TcpTransceiver(int transID);

    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const uint8_t* buf, size_t size);
    virtual void SetConnectionID(int connID);
    virtual ConnectionType ConnType();

    // Implement Resource Interface
    virtual void Reset();
    
    // Implement TcpCoreUser Interfaces
    virtual evutil_socket_t Socket();
    virtual uint32_t OnDataReceived(Buffer::Ptr spBuf);
    virtual void     OnBytesSent(uint32_t bytesSent);
    virtual void     OnBytesRecv(uint32_t bytesRecv);
    virtual void     OnDisconnect();
    virtual void     OnReadError(int error);
    virtual void     OnWriteError(int error);
    virtual void     OnReadTimeout();
    
    virtual Buffer::Ptr GetBuffer(uint32_t bufSize);
    virtual Buffer::Ptr GetBuffer(Buffer::Ptr spBuf);
    
    // Implement TlsCoreUser Interfaces
    virtual void OnDataEncrypted(Buffer::Ptr spData);
    virtual void OnDataDecrypted(Buffer::Ptr spData);
    virtual void OnInternalError();
    
    virtual Buffer::Ptr GetTlsBuffer(uint32_t bufSize);
    
    // Start with connected socket (handling incoming client)
    //
    //   Used by TCP listener & FW server
    //
    bool Start(evutil_socket_t sock);
    
    // Start the TcpTransceiver with connection
    // established with HTTP Proxy by CURL
    //
    void PrepareProxyConnect();
    void StartAfterProxyConnect();
        
    // Setting/Getting TcpState to handle Firewall Traversal state machine
    void SetState(TcpTxrxState::Type type, bool initial = false);
    TcpTxrxState::Type GetStateType();
    TcpTxrxState::Type GetSetupMethodType();
    
    // Data after processed by TcpTxrxState
    void OnDataProcessed(Buffer::Ptr spBuf);
    
    void EnableTcpFramer();
    void SendMapData(); // send mapping message to client for debugging purpose
    
    // query for current send queue size
    void     GetSendQInfo(size_t& rNum, uint32_t& rBufSize);
    uint32_t GetSendRetryCount();
    
    // available only for framing mode
    void SendStat(uint8_t type, uint16_t rateKbps, uint32_t seqNum);
    
private:
    
    // set various options we want socket
    void SetSocketOption();
    
    // Interface for libevent callback
    static void OnLibEvent(evutil_socket_t sock, short what, void* pArg);
    void OnConnectedEvent();
    
    static const uint16_t CONNECT_TIMEOUT = 5000; // wait up to 5 seconds
    
    evutil_socket_t    socket_;
    int                connID_;
    ConnectionImpl*    pConn_;      // cache to avoid using ResourceMgr
    bool               bConnected_; // flag that indicate we are connected
    TcpCore            tcpCore_;
    Address            remote_;
    TlsCore::Ptr       spTlsCore_;  // stucture to handle TLS connection
    ConnectInfo::Ptr   spConnect_;  // shared_ptr of HTTP connect stuff
    
private: // TCP frame mode
    static const uint32_t MAX_MTU_SIZE = 18000; // only when DataOverTls
                                                // TLS can't exceed 18432B
    bool               bUseFrame_;  // enable WYSWYG mode
    TcpFramer          tcpFramer_;
    MutexLock          sendLock_;   // synchronize order of data into sendQ
    
private: // state pattern to separate the behavior on different state
    TcpTxrxState*      pState_;
    TcpTxrxState::Type setupMethod_;  // method used to connect
    
    friend class StateTcp;
    friend class StateTls;
    friend class StateUdpOverTcp;
    friend class StateSetupTcp;
    friend class StateSetupTcpPort443;
    friend class StateSetupHttp;
    friend class StateSetupTls;
    friend class StateSetupMapTls;
    friend class StateDataOverTls;
    friend class StateHttpTls;
    friend class Server; // need to send Fuze msg straight

    // Helper to make state transition easier
    Buffer::Ptr  MakeMapRequest();
    uint32_t     OnMapResponse(Buffer::Ptr spBuf);
    string       mapResponse_; // to collect entire MAP response for TLS
    
private: // helper
    static const size_t Q_LIMIT = 3000000; // 3MB
    static const size_t Q_SIZE  = 300;
    
    int64_t      lastSendError_; // to limit send error log
    int64_t      lastDropTime_;  // impose queue size limit
    uint32_t     dropCnt_;
};

} // namespace fuze

#endif /* defined(__FuzeTransport__TcpTransceiver__) */
