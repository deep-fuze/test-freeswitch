//
//  DtlsTransceiver.h
//  FuzeTransport
//
//  Created by Tim Na on 12/4/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__DtlsTransceiver__
#define __FuzeTransport__DtlsTransceiver__

#include <Transceiver.h>
#include <TlsCore.h>
#include <SecureRTP.h>

namespace fuze {
    
class DtlsTransceiver : public Transceiver
                      , public TlsCoreUser
{
public:
    explicit DtlsTransceiver(int transID);
    
    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const uint8_t* buf, size_t size);
    virtual void SetConnectionID(int connID);
    virtual ConnectionType ConnType();
    
    // Implement Resource Interface
    virtual void Reset();
    
    // Implement TlsCoreUser interface
    virtual void OnDataEncrypted(Buffer::Ptr spData);
    virtual void OnDataDecrypted(Buffer::Ptr spData);
    virtual void OnInternalError();
    
    virtual Buffer::Ptr GetTlsBuffer(uint32_t bufSize);

    // DTLS has client or server role
    void SetConnectionType(ConnectionType eType);
    
private:
    void Init();
    void DoDtlsHandshake();
    bool SetReadEvent(uint16_t timeout = 0);
    bool SetWriteEvent();    // could be set by application thread
    void RemoveWriteEvent(); // remove by libevent thread
    
    const char* LogMsg(const char* pMsg, uint32_t size);
    
    // Interface for libevent callback
    static void OnLibEvent(evutil_socket_t sock, short what, void* pArg);
    void OnReadEvent();
    void OnWriteEvent();
    void OnTimeOutEvent();

    void EncryptAndSend(uint8_t* p_buf, uint32_t buf_len);
    void SendData(Buffer::Ptr spData, const Address& rRemote);
    
    static const int    MAX_UDP_SIZE = 65535;
    
    ConnectionType      connType_;
    
    int                 connID_;
    ConnectionImpl*     pConn_;
    
    evutil_socket_t     socket_;

    event*              pReadEvent_;
    int32_t             readTimeout_;
    event*              pWriteEvent_;
    bool                writeAdded_;
    
    queue<Buffer::Ptr>  sendQ_;
    MutexLock           qLock_;
    
    char                buffer_[MAX_UDP_SIZE];

    int64_t             lastStunTime_;

private: // DTLS specific members
    enum DtlsState { INIT, HANDSHAKING, ESTABLISHED };
    
    const char* StateStr(DtlsState eState);
    
    DtlsState           dtlsState_;
    DtlsCore*           pDtlsCore_;
    SRTP                srtp_;
    
private: // debugging
    
    char                pName_[16];
    int                 logCnt_;
    int                 stunCnt_;
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__DtlsTransceiver__) */
