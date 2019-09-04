//
//  Message.h
//  FuzeTransport
//
//  Created by Tim Na on 1/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#ifndef __FuzeTransport__Message__
#define __FuzeTransport__Message__

#include <Transport.h>

namespace fuze {
    
class ByteStream
{
public:
    virtual Buffer::Ptr Serialize() = 0;
    virtual void Parse(const uint8_t* pMsg, uint32_t msgLen) = 0;
    
    inline virtual ~ByteStream()
    {
    }
};

class MsgBody : public ByteStream
{
public:
    enum Type { INVALID, MAP };
    
    typedef fuze_shared_ptr<MsgBody> Ptr;
    
    MsgBody() : type_(INVALID) {}
    
    virtual Type GetType() = 0;
    
protected:
    Type type_;
};
    
// parser helper methods
namespace msg
{
    enum Type
    {
        INVALID,
        FUZE,
        HTTP,
        TLS
    };
    
    Type        get_type(uint8_t* pBuf, uint32_t bufLen);
    uint32_t    get_length(uint8_t* pBuf, uint32_t bufLen);
    
    bool        is_fuze_data(uint8_t firstByte);
    bool        is_http(uint8_t* pFirstByte, uint32_t len);
    bool        is_http_response(uint8_t* pFirstByte, uint32_t len);
    
    uint32_t    get_http_length(uint8_t* pFirstByte, uint32_t len);
    
    const char* find_header_value(const char* pMsg,
                                  const char* pHeader);
    
    bool        is_tls(uint8_t firstByte);
    uint16_t    get_tls_app_length(uint8_t* pFirstByte, uint32_t len);
    
} // namespace msg

const char* toStr(msg::Type type);
    
} // namespace fuze

#endif // __FuzeTransport__Message__