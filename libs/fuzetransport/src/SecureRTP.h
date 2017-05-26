//
//  SecureRTP.hpp
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef SecureRTP_h
#define SecureRTP_h

#include <Secure.h>
#include <MutexLock.h>

#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
// The clients use libsrtp2.
#include <srtp2/srtp.h>
#else
#ifndef FREE_SWITCH
// The hubs still use libsrtp 1.x because opal still depends on it.
#include <srtp/srtp.h>
#else
#include <srtp.h>
#endif
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80 crypto_policy_set_aes_cm_128_hmac_sha1_80
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32 crypto_policy_set_aes_cm_128_hmac_sha1_32
#define srtp_crypto_policy_set_aes_cm_128_null_auth crypto_policy_set_aes_cm_128_null_auth
#define srtp_crypto_policy_set_rtcp_default crypto_policy_set_rtcp_default
#endif

namespace fuze {
    
class SRTP : public SecureRTP
{
public:
    typedef fuze_shared_ptr<SRTP> Ptr;
    
    SRTP();
    virtual ~SRTP();
    
    virtual string GetLocalKey(KeyType type);
    virtual void   SetRemoteKey(KeyType type, const string& rRemoteKey);
    virtual string GetRemoteKey();
    
    virtual int GetAuthTagLen(bool isRtp) const {return (send_policy_ ? (isRtp ? send_policy_->rtp.auth_tag_len : send_policy_->rtcp.auth_tag_len) : 0);}
    virtual void SetWindowSize(unsigned long windowSize) {window_size_ = windowSize;}

    virtual void Encrypt(uint8_t* data, int* bytes_out);
    virtual void Decrypt(uint8_t* data, int* bytes_out);
    
    virtual void EncryptRTCP(uint8_t* data, int* bytes_out);
    virtual void DecryptRTCP(uint8_t* data, int* bytes_out);

public: // internal transport API
    
    struct SrtpCtx
    {
        uint8_t             key_[SRTP_MASTER_KEY_LEN];
        uint32_t            key_len_;
        SecureRTP::KeyType  key_type_;
        
        SrtpCtx();
        
        int SetKey(KeyType type, uint8_t* key, uint32_t len);
    };
    
    enum Direction { SEND, RECV };

    void Reset();
    
    int  SetSRTPKey(Direction dir, KeyType type, uint8_t* key, uint32_t key_len);
    
private:
    
    int ApplySRTPKey(Direction dir);
    
    uint8_t         local_srtp_key_[3][SRTP_MASTER_KEY_LEN];
    string          remote_key;
    
    srtp_ctx_t*     send_ctx_;
    srtp_ctx_t*     recv_ctx_;
    
    srtp_policy_t*  send_policy_;
    srtp_policy_t*  recv_policy_;
    
    SrtpCtx         send_local_ctx_;
    SrtpCtx         recv_local_ctx_;
    
    bool            has_new_send_key_;
    bool            has_new_recv_key_;
    
    MutexLock       key_lock_;

    unsigned long   window_size_;
};


} // namespace fuze

#endif /* SecureRTP_h */
