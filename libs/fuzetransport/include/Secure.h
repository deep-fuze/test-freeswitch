//
//  Secure.h
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef Fuze_Secure_h
#define Fuze_Secure_h


#include "Common.h"

namespace fuze {
    
class SecureRTP
{
public:
    typedef fuze_shared_ptr<SecureRTP> Ptr;
    
    enum KeyType
    {
        AES_CM_128_HMAC_SHA1_32,
        AES_CM_128_HMAC_SHA1_80,
        AES_CM_128_NULL_AUTH
    };
    
    static Ptr Create();
    
    static const uint32_t MAX_TRAILER_LEN = 16;
    
    virtual string GetLocalKey(KeyType type) = 0;
    virtual void   SetRemoteKey(KeyType type, const string& rRemoteKey) = 0;
    virtual string GetRemoteKey() = 0;
    
    // Functions for encrypt and decrypt will write the result data
    // to the input buffer only. Incase of encrypt, more data than
    // input could be written.
    virtual void Encrypt(uint8_t* data, int* bytes_out) = 0;
    virtual void Decrypt(uint8_t* data, int* bytes_out) = 0;
    
    virtual void EncryptRTCP(uint8_t* data, int* bytes_out) = 0;
    virtual void DecryptRTCP(uint8_t* data, int* bytes_out) = 0;
    
    virtual ~SecureRTP() {}
};

//
// SRTP key encode/decode
//
int EncodeSrtpKeyBase64(const char* pData, uint32_t len, char* pBuf);
int DecodeSrtpKeyBase64(const char* pData, uint32_t len, char* pBuf);

SecureRTP::KeyType GetSrtpKeyType(const char* type);
const char*        GetSrtpKeyTypeStr(SecureRTP::KeyType key_type);

} // namespace fuze

#endif /* Fuze_Secure_h */
