//
//  TlsCore.h
//  FuzeTransport
//
//  Created by Tim Na on 2/26/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TlsCore__
#define __FuzeTransport__TlsCore__

#include <Transport.h>
#include <openssl/ssl.h>
#include <MutexLock.h>

namespace fuze {

//
// TlsCoreUser is observer that recieves openssl event
//
class TlsCoreUser
{
public:
    // when data is encrypted, TlsCoreUser is
    // responsible of sending it over socket interface.
    // This interface is invoked when we feed plain data
    // into TlsCore object
    virtual void OnDataEncrypted(Buffer::Ptr spData) = 0;
    
    // when data is decrypted, TlsCoreUser is
    // responsible of delivering it to Application layer.
    // This interface is invoked when we feed encrypted
    // data we receieved from far end TLS node.
    virtual void OnDataDecrypted(Buffer::Ptr spData) = 0;
    
    // Fatal error occurred - TlsCoreUser must take
    // action to take down the connection.
    virtual void OnInternalError() = 0;
    
    virtual Buffer::Ptr GetTlsBuffer(uint32_t bufSize) = 0;
    
    inline virtual ~TlsCoreUser() {}
};

//
// TlsCore is data structure encapsulates openssl
//
class TlsCore
{
public:
    typedef fuze_shared_ptr<TlsCore> Ptr;
    
    TlsCore(TlsCoreUser& rUser, bool bServer = false);
    virtual ~TlsCore();
    
    void Init();
    
    // TLS Client must initiate handshake
    void TriggerHandshake();
    
    // query to see if we are still in handshake pahse
    bool IsInHandshake();
    
    enum ProcessType { PT_ENCRYPT, PT_DECRYPT };
    
    uint32_t ProcessData(uint8_t* pData, uint32_t dataLen, ProcessType type);
    
    const char* GetVersion();
    
public: // exceptional member variable to be exposed
    
    char log_[64];  // debug purpose
    
protected:
    
    virtual void InitSSL();
    
    static void InitCertificate(SSL_CTX* pCtx, bool makeCerticate = false);

    static const size_t TLS_BUF_SIZE = 18432*2; // max length is 18432

    static SSL_CTX*  pTlsCtx_;  // TLS global context structure
    static MutexLock ctxLock_;
    
    static char      fingerPrint_[EVP_MAX_MD_SIZE*3]; // we need to add ':'
    
    TlsCoreUser&     rCoreUser_;
    bool             bServer_;
    
    SSL*             pSSL_;
    BIO*             pBioSSL_;  // SSL filter BIO
    BIO*             pWrapSSL_; // pseudo-I/O for SSL library
    BIO*             pBioIO_;   // network interfacing BIO
    
    friend int  ssl_verify_peer(int, X509_STORE_CTX*);
    friend void ssl_state(const SSL*, int, int);
};

class DtlsCore : public TlsCore
{
public:
    DtlsCore(TlsCoreUser& rUser, bool bServer = false);

    static const char* GetFingerPrint();
    
    // DTLS specific function for handling timeout case
    bool GetTimeout(int32_t& rTimeout);
    bool HandleTimeout();
    
    // Needed for ClientHello Verification case using cookie
    bool ClientHelloVerified();

    const char* GetSelectSrtpProfile();
    bool GetSrtpKeyMaterial(uint8_t* material);
    
    static const int SRTP_M_KEY_LEN  = 16;
    static const int SRTP_M_SALT_LEN = 14;
    static const int SRTP_M_LEN = SRTP_M_KEY_LEN + SRTP_M_SALT_LEN;
    
protected:
    virtual void InitSSL();
    static  void InitDtlsCertificate(SSL_CTX*& rpCtx, bool bServer);
    
    static SSL_CTX*  pDtlsCCtx_; // DTLS client context structure
    static SSL_CTX*  pDtlsSCtx_; // DTLS server context structure
    
#ifdef COOKIE_ENABLED
    int              cookieID_;  // unique id for DTLS cookie
    static int       IDs_;       // ID generator
    
    friend int generate_cookie(SSL*, unsigned char*, unsigned int*);
    friend int verify_cookie(SSL*, unsigned char*, unsigned int);
#endif
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__TlsCore__) */
