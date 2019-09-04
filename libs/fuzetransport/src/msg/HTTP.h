//
//  HTTP.h
//  FuzeTransport
//
//  Created by Tim Na on 2/3/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__HTTP__
#define __FuzeTransport__HTTP__

#include <Message.h>

namespace fuze {
namespace tp {
    
class Http : public ByteStream
{
public:
    Http() : v11_(false) {}
    
    MsgBody::Ptr GetMsgBody() { return spBody_; }
    void SetMsgBody(MsgBody::Ptr spBody) { spBody_ = spBody; }
    
protected:
    bool          v11_; // HTTP/1.1
    MsgBody::Ptr  spBody_;
};
    
const uint32_t HTTP_SIZE = 1024 * 2;

class HttpRequest : public Http
{
public:
    enum Type { INVALID, CONNECT, GET, PUT, POST };
    
    typedef fuze_shared_ptr<HttpRequest> Ptr;
    
    HttpRequest();
    HttpRequest(Type type);
    
    // static helper method
    static Type ParseMethodType(char* pBuf, uint32_t len);
    
    // ByteStream Interface
    virtual Buffer::Ptr Serialize();
    virtual void Parse(const uint8_t* pMsg, uint32_t msgLen);
    
    void   SetRequestURI(const string& rReqURI);
    void   SetMethodType(Type type);
    
    const string& GetRequestURI();
    Type          GetMethodType();
    
private:
    
    string  requestURI_;
    Type    type_;
};

const char* toStr(HttpRequest::Type type);
    
class HttpResponse : public Http
{
public:
    HttpResponse();
    
    typedef fuze_shared_ptr<HttpResponse> Ptr;
    
    // ByteStream Interface
    virtual Buffer::Ptr Serialize();
    virtual void Parse(const uint8_t* pMsg, uint32_t msgLen);
    
    uint32_t GetResponseCode();
    string   GetReason();
    
    void SetResponseLine(uint32_t code, const char* pReason);
    
private:

    uint32_t  responseCode_;
    string    reason_;
};

} // namespace tp
} // namespace fuze


#endif /* defined(__FuzeTransport__HTTP__) */
