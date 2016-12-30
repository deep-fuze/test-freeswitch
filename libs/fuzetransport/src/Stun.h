//
//  Stun.h
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#ifndef Stun_h
#define Stun_h

#include <Transport.h>
#include <Address.h>

namespace fuze {
namespace stun {
    
using fuze::Address;
    
enum Method
{
    UNKNOWN,
    BINDING = 0x0001
};

enum Type
{
    INVALID,
    REQUEST,
    INDICATION,
    SUCCESS,
    FAILURE
};

enum Attribute
{
    USERNAME           = 0x0006,
    MESSAGE_INTEGRITY  = 0x0008,
    XOR_MAPPED_ADDRESS = 0x0020,
    PRIORITY           = 0x0024,
    USE_CANDIDATE      = 0x0025,
    FINGERPRINT        = 0x8028,
    ICE_CONTROLLED     = 0x8029,
    ICE_CONTROLLING    = 0x802a
};

bool   IsStun(const char* pMsg, uint32_t size);

Type   GetType(const char* pMsg, uint32_t size);
Method GetMethod(const char* pMsg, uint32_t size);
bool   GetTransactionID(const char* pMsg,
                        uint32_t    size,
                        uint8_t*    pTransID); // must have 12 bytes allocated

bool   Validate(const char*   pMsg,
                uint32_t      size,
                const string& rPwd,
                bool          bNoLog = false);

void PrintStun(const char* pMsg, uint32_t size);

void CreateBindResponse(Buffer::Ptr    spResp,
                        const uint8_t* pTransID,
                        const Address& rAddress,
                        const string&  rPwd);

void CreateBindRequest(Buffer::Ptr    spReq,
                       const string&  username,
                       const uint8_t* transID,
                       const string&  rPwd,
                       bool           bNoIce = false);
    
} // namespace stun

const char* toStr(stun::Type eType);
const char* toStr(stun::Method type);
const char* toStr(stun::Attribute eAttr);

} // namespace fuze


#endif /* Stun_h */
