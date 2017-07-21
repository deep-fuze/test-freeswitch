//
//  SecureRTP.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#include <SecureRTP.h>
#include <Transport.h>
#include <Log.h>
#include <cassert>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

void fuze_srtp_init()
{
#ifndef FREE_SWITCH
    _MLOG_("version: " << srtp_get_version_string());
#endif
    srtp_init();
}

char base64_encode_value(char value_in)
{
    static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (value_in > 63) return '=';
    return encoding[(int)value_in];
}

int EncodeSrtpKeyBase64(const char* pData, uint32_t len, char* pBuf)
{
    enum base64_encodestep { step_A, step_B, step_C };

    struct base64_encodestate
    {
        base64_encodestep step;
        char              result;
        int               stepcount;
    } state = { step_A, 0, 0 };

    const char* plainchar = pData;
    const char* const plaintextend = pData + len;
    char* codechar = pBuf;

    char result = state.result;
    char fragment;

    switch (state.step)
    {
        while (1)
        {
        case step_A:
            if (plainchar == plaintextend) {
                state.result = result;
                state.step = step_A;
                return (int)(codechar - pBuf);
            }
            fragment = *plainchar++;
            result = (fragment & 0x0fc) >> 2;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x003) << 4;
        case step_B:
            if (plainchar == plaintextend) {
                state.result = result;
                state.step = step_B;
                return (int)(codechar - pBuf);
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0f0) >> 4;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x00f) << 2;
        case step_C:
            if (plainchar == plaintextend) {
                state.result = result;
                state.step = step_C;
                return (int)(codechar - pBuf);
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0c0) >> 6;
            *codechar++ = base64_encode_value(result);
            result  = (fragment & 0x03f) >> 0;
            *codechar++ = base64_encode_value(result);

            ++(state.stepcount);
            if (state.stepcount == 18) {
                *codechar++ = '\n';
                state.stepcount = 0;
            }
        }
    }

    /* control should not reach here */
    return codechar - pBuf;
}

int base64_decode_value(char value_in)
{
    static const int decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
    static const int decoding_size = sizeof(decoding);
    value_in -= 43;
    if (value_in < 0 || (int)value_in > decoding_size) return -1;
    return decoding[(int)value_in];
}

int DecodeSrtpKeyBase64(const char* pData, uint32_t len, char* pBuf)
{
    enum base64_decodestep { step_a, step_b, step_c, step_d };

    struct base64_decodestate
    {
        base64_decodestep step;
        char              plainchar;
    } state = { step_a, 0 };

    const char* codechar = pData;
    char* plainchar = pBuf;
    char fragment;

    *plainchar = state.plainchar;

    switch (state.step)
    {
        while (1)
        {
        case step_a:
            do {
                if (codechar == pData+len) {
                    state.step = step_a;
                    state.plainchar = *plainchar;
                    return (int)(plainchar - pBuf);
                }
                fragment = (char)base64_decode_value(*codechar++);
            } while (fragment < 0);
            *plainchar    = (fragment & 0x03f) << 2;
        case step_b:
            do {
                if (codechar == pData+len) {
                    state.step = step_b;
                    state.plainchar = *plainchar;
                    return (int)(plainchar - pBuf);
                }
                fragment = (char)base64_decode_value(*codechar++);
            } while (fragment < 0);
            *plainchar++ |= (fragment & 0x030) >> 4;
            *plainchar    = (fragment & 0x00f) << 4;
        case step_c:
            do {
                if (codechar == pData+len) {
                    state.step = step_c;
                    state.plainchar = *plainchar;
                    return (int)(plainchar - pBuf);
                }
                fragment = (char)base64_decode_value(*codechar++);
            } while (fragment < 0);
            *plainchar++ |= (fragment & 0x03c) >> 2;
            *plainchar    = (fragment & 0x003) << 6;
        case step_d:
            do {
                if (codechar == pData+len) {
                    state.step = step_d;
                    state.plainchar = *plainchar;
                    return (int)(plainchar - pBuf);
                }
                fragment = (char)base64_decode_value(*codechar++);
            } while (fragment < 0);
            *plainchar++   |= (fragment & 0x03f);
        }
    }

    /* control should not reach here */
    return plainchar - pBuf;
}


SecureRTP::Ptr SecureRTP::Create()
{
    SecureRTP::Ptr sp_srtp(new SRTP);
    return sp_srtp;
}

SecureRTP::KeyType GetSrtpKeyType(const char* type)
{
    if (!type) {
        return SecureRTP::AES_CM_128_NULL_AUTH;
    }

    if (!strcmp(type, "AES_CM_128_HMAC_SHA1_80") ||
        !strcmp(type, "SRTP_AES128_CM_SHA1_80")) {
        return SecureRTP::AES_CM_128_HMAC_SHA1_80;
    }

    if (!strcmp(type, "AES_CM_128_HMAC_SHA1_32") ||
        !strcmp(type, "SRTP_AES128_CM_SHA1_32")) {
        return SecureRTP::AES_CM_128_HMAC_SHA1_32;
    }

    return SecureRTP::AES_CM_128_NULL_AUTH;
}

const char* GetSrtpKeyTypeStr(SecureRTP::KeyType key_type)
{
    switch(key_type)
    {
    case SecureRTP::AES_CM_128_HMAC_SHA1_80: return "AES_CM_128_HMAC_SHA1_80";
    case SecureRTP::AES_CM_128_HMAC_SHA1_32: return "AES_CM_128_HMAC_SHA1_32";
    case SecureRTP::AES_CM_128_NULL_AUTH:    return "AES_CM_128_NULL_AUTH";
    default:                                 return "NONE";
    }
}

SRTP::SrtpCtx::SrtpCtx()
    : key_len_(0)
{
}

int SRTP::SrtpCtx::SetKey(KeyType type, uint8_t* key, uint32_t len)
{
    if (!key) {
        ELOG("Invalid SRTP key.");
        return -1;
    }

    if (len > sizeof(key_)) {
        ELOG("SRTP Key length greater than " << sizeof(key_));
        return -1;
    }

    key_type_ = type;
    memcpy(key_, key, len);
    key_len_ = len;

    return 0;
}

void SetRandomKey(uint8_t key[SRTP_MASTER_KEY_LEN])
{
    // http://c-faq.com/lib/randrange.html
    static int divisor = RAND_MAX / 255 + 1;

    for (size_t i = 0; i < SRTP_MASTER_KEY_LEN-1; ++i) {
        key[i] = rand()/divisor;
    }
}

SRTP::SRTP()
    : send_ctx_(0)
    , recv_ctx_(0)
    , send_policy_(new srtp_policy_t)
    , recv_policy_(new srtp_policy_t)
    , has_new_send_key_(false)
    , has_new_recv_key_(false)
    , window_size_(128)
{
    memset(send_policy_, 0, sizeof(srtp_policy_t));
    memset(recv_policy_, 0, sizeof(srtp_policy_t));

    SetRandomKey(local_srtp_key_[0]);
    SetRandomKey(local_srtp_key_[1]);
}

SRTP::~SRTP()
{
    if (send_ctx_)    srtp_dealloc(send_ctx_);
    if (recv_ctx_)    srtp_dealloc(recv_ctx_);
    if (send_policy_) delete send_policy_;
    if (recv_policy_) delete recv_policy_;
}

void SRTP::Reset()
{
    if (send_ctx_) {
        srtp_dealloc(send_ctx_);
        send_ctx_ = 0;
    }
    if (recv_ctx_) {
        srtp_dealloc(recv_ctx_);
        recv_ctx_ = 0;
    }

    if (send_policy_) {
        memset(send_policy_, 0, sizeof(srtp_policy_t));
    }

    if (recv_policy_) {
        memset(recv_policy_, 0, sizeof(srtp_policy_t));
    }

    send_local_ctx_.key_len_ = 0;
    recv_local_ctx_.key_len_ = 0;

    has_new_send_key_ = false;
    has_new_recv_key_ = false;
}

string SRTP::GetLocalKey(SecureRTP::KeyType type)
{
    char b64_key[(SRTP_MASTER_KEY_LEN * 8 / 6) + 2];

    int keylen = EncodeSrtpKeyBase64((char*)local_srtp_key_[type],
                                     sizeof(local_srtp_key_[type]), b64_key);

    b64_key[keylen] = 0;
    char* p = strrchr((char *) b64_key, '=');
    while (p && *p && *p == '=') {
        *p-- = '\0';
    }

    return b64_key;
}

string SRTP::GetRemoteKey()
{
    return remote_key;
}

void SRTP::SetRemoteKey(KeyType keyType, const string& rRemoteKey)
{
    KeyType type = AES_CM_128_HMAC_SHA1_80;

    if (keyType == SecureRTP::AES_CM_128_HMAC_SHA1_32) {
        type = AES_CM_128_HMAC_SHA1_32;
    }

    SetSRTPKey(SEND, type, local_srtp_key_[type], sizeof(local_srtp_key_[type]));

    // cache the key to check if there is a change
    remote_key = rRemoteKey;

    //    DLOG("SRTP: Final Keys: Local=" << Hex(local_srtp_key_, SRTP_MASTER_KEY_LEN) <<
    //         " Remote=" << rRemoteKey);

    uint8_t raw_key[SRTP_MASTER_KEY_LEN];

    int keylen = DecodeSrtpKeyBase64(remote_key.c_str(), remote_key.size(), (char*)raw_key);

    SetSRTPKey(RECV, type, raw_key, keylen);
}

int SRTP::SetSRTPKey(Direction dir, KeyType type, uint8_t* key, uint32_t key_len)
{
    int ret;
    SrtpCtx *local_ctx;

    MLOG((dir == RECV ? "RECV " : "SEND ") << GetSrtpKeyTypeStr(type));

    switch (dir)
    {
    case RECV:
        local_ctx = &recv_local_ctx_;
        break;
    case SEND:
        local_ctx = &send_local_ctx_;
        break;
    default:
        assert(0);
        return -1;
    }

    /*
     * Since the encrypt/decrypt are done in different thread context,
     * lets store the information and set the flag.
     */
    if ((ret = local_ctx->SetKey(type, key, key_len))) {
        return ret;
    }

    if (dir == SEND) {
        has_new_send_key_ = true;
    }
    else {
        has_new_recv_key_ = true;
    }

    return 0;
}

int SRTP::ApplySRTPKey(Direction dir)
{
    int ret;
    srtp_policy_t* policy = 0;
    srtp_ctx_t** ctx = 0;
    SrtpCtx* local_ctx = 0;

    switch (dir)
    {
    case RECV:
        local_ctx = &recv_local_ctx_;
        ctx       = &recv_ctx_;
        policy    = recv_policy_;
        policy->ssrc.type = ssrc_any_inbound;
        MLOG("Setting keys for RECV: type=" <<
             GetSrtpKeyTypeStr(local_ctx->key_type_));
        break;
    case SEND:
        local_ctx = &send_local_ctx_;
        ctx       = &send_ctx_;
        policy    = send_policy_;
        policy->ssrc.type = ssrc_any_outbound;
        MLOG("Setting keys for SEND: type=" <<
             GetSrtpKeyTypeStr(local_ctx->key_type_));
        break;
    default:
        assert(0);
        return -1;
    }

    if (*ctx) {
        srtp_dealloc(*ctx);
        *ctx = NULL;
    }

    switch (local_ctx->key_type_)
    {
    case AES_CM_128_HMAC_SHA1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtp);
        break;
    case AES_CM_128_HMAC_SHA1_32:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtp);
        break;
    case AES_CM_128_NULL_AUTH:
        srtp_crypto_policy_set_aes_cm_128_null_auth(&policy->rtp);
        break;
    default:
        assert(0);
        return -1;
    }

    policy->key             = local_ctx->key_;
    policy->rtp.sec_serv    = sec_serv_conf_and_auth;
    policy->allow_repeat_tx = 1;
    policy->window_size     = window_size_;

    srtp_crypto_policy_set_rtcp_default(&policy->rtcp);

    if ((ret = srtp_create(ctx, policy))) {
        *ctx = NULL;
        ELOG("SRTP: Error in srtp_create() for RECV side : " << ret);
        return ret;
    }

    return 0;
}

void SRTP::Encrypt(uint8_t* data, int* bytes_out)
{
    if (has_new_send_key_ == true) {
        MutexLock scoped(&key_lock_);
        if (has_new_send_key_ == true) { //Double check to avoid race conditions.
            ApplySRTPKey(SEND);
            has_new_send_key_ = false;

            if (!send_ctx_) {
                ELOG("SRTP: no encrypt key has been created yet");
                return;
            }
        }
    }

    if (!data || !(*bytes_out) || !send_ctx_) {
        return;
    }

    int ret = 0;
    {
        MutexLock scoped(&srtp_protect_lock_);
        ret = srtp_protect(send_ctx_, data, bytes_out);
    }
    if (ret) {
        ELOG("SRTP: Error in srtp_protect() : " << ret);
        *bytes_out = 0;
    }
}

void SRTP::Decrypt(uint8_t* data, int* bytes_out)
{
    if (has_new_recv_key_ == true) {
        MutexLock scoped(&key_lock_);
        if (has_new_recv_key_ == true) { //Double check to avoid race conditions.
            ApplySRTPKey(RECV);
            has_new_recv_key_ = false;

            if (!recv_ctx_) {
                ELOG("SRTP: no encrypt key has been created yet");
                return;
            }
        }
    }

    if (!data || !(*bytes_out) || !recv_ctx_) {
        return;
    }

    if (int ret = srtp_unprotect(recv_ctx_, data, bytes_out)) {
        ELOG("SRTP: Error in srtp_unprotect() : " << ret);
        *bytes_out = 0;
    }
}

void SRTP::EncryptRTCP(uint8_t* data, int *bytes_out)
{
    if (has_new_send_key_ == true) {
        MutexLock scoped(&key_lock_);
        if (has_new_send_key_ == true) { //Double check to avoid race conditions.
            ApplySRTPKey(SEND);
            has_new_send_key_ = false;

            if (!send_ctx_) {
                ELOG("SRTP: no encrypt key has been created yet");
                return;
            }
        }
    }

    if (!data || !(*bytes_out) || !send_ctx_) {
        return;
    }

    //int orig_len = *bytes_out;
    int ret = 0;
    {
        MutexLock scoped(&srtp_protect_lock_);
        ret = srtp_protect_rtcp(send_ctx_, data, bytes_out);
    }
    if (ret) {
        ELOG("SRTCP: Error in srtp_protect_rtcp() : " << ret);
        *bytes_out = 0;
    }

    //TLOG("SRTCP: encrypt: In=" << orig_len << " Out=" << *bytes_out);
}

void SRTP::DecryptRTCP(uint8_t* data, int *bytes_out)
{
    if (has_new_recv_key_ == true) {
        MutexLock scoped(&key_lock_);
        if (has_new_recv_key_ == true) { //Double check to avoid race conditions.
            ApplySRTPKey(RECV);
            has_new_recv_key_ = false;

            if (!recv_ctx_) {
                ELOG("SRTP: no decrypt key has been created yet");
                return;
            }
        }
    }

    if (!data || !(*bytes_out) || !recv_ctx_) {
        return;
    }

    //int orig_len = *bytes_out;
    if (int ret = srtp_unprotect_rtcp(recv_ctx_, data, bytes_out)) {
        ELOG("SRTCP: Error in srtcp_unprotect() : " << ret);
        *bytes_out = 0;
    }

    //TLOG("SRTCP: decrypt: In=" << orig_len << " Out="  << *bytes_out);
}

} // namespace fuze
