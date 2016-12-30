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

#ifdef DTLS_SRTP
struct srtp_ctx_t;
struct srtp_policy_t;
#endif

namespace fuze {

#ifdef DTLS_SRTP
class SRTP
{
public:
    SRTP();
    virtual ~SRTP();
    
    void Reset();
    
    enum Direction { SEND, RECV };
    enum KeyType
    {
        AES_CM_128_NULL_AUTH,
        AES_CM_128_HMAC_SHA1_80,
        AES_CM_128_HMAC_SHA1_32
    };
    
    int SetSRTPKey(Direction  dir,
                   KeyType    type,
                   uint8_t*   key,
                   uint32_t   key_len);
    
    // Functions for encrypt and decrypt will write the result data
    // to the input buffer only. Incase of encrypt, more data than
    // input could be written.
    void Encrypt(uint8_t* data, int* bytes_out);
    void Decrypt(uint8_t* data, int* bytes_out);
    
    void EncryptRTCP(uint8_t* data, int* bytes_out);
    void DecryptRTCP(uint8_t* data, int* bytes_out);
    
    static const int SRTP_KEY_SIZE = 30;
    static const int SRTP_MAX_TRAILER_LEN = 12;
    
private:

    struct Ctx
    {
        uint8_t  key_[SRTP_KEY_SIZE];
        uint32_t key_len_;
        KeyType  key_type_;
        
        Ctx();
        int SetKey(KeyType type, uint8_t* key, uint32_t len);
    };
    
    int ApplySRTPKey(Direction dir);
    
    uint8_t local_srtp_key_[SRTP_KEY_SIZE];
    
    srtp_ctx_t*     send_ctx_;
    srtp_ctx_t*     recv_ctx_;
    
    srtp_policy_t*  send_policy_;
    srtp_policy_t*  recv_policy_;
    
    Ctx             send_local_ctx_;
    Ctx             recv_local_ctx_;
    
    bool            has_new_send_key_;
    bool            has_new_recv_key_;
    
    MutexLock       key_lock_;
};

SRTP::KeyType toSRTPKeyType(const char* type);
const char*   toStr(SRTP::KeyType key_type);
#endif
    
class DtlsTransceiver : public Transceiver
                      , public TlsCoreUser
{
public:
    explicit DtlsTransceiver(int transID);
    
    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const unsigned char* buf, size_t size);
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
    void onWriteEventInternal(uint8_t* p_buf, uint32_t buf_len);
    void OnTimeOutEvent();
    
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
#ifdef DTLS_SRTP
    SRTP                srtp_;
#endif
    
private: // debugging
    
    char                pName_[16];
    int                 logCnt_;
    int                 stunCnt_;
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__DtlsTransceiver__) */
