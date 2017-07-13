//
//  HTTP.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/3/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <HTTP.h>
#include <Mapping.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "http::" << __FUZE_FUNC__ << ": " << B)

namespace fuze {
namespace tp {

const char* toStr(HttpRequest::Type type)
{
    switch (type)
    {
    case HttpRequest::CONNECT: return "CONNECT";
    case HttpRequest::GET:     return "GET";
    case HttpRequest::PUT:     return "PUT";
    case HttpRequest::POST:    return "POST";
    default:                   return "INVALID";
    }
}

HttpRequest::HttpRequest()
    : type_(INVALID)
{
}

HttpRequest::HttpRequest(Type type)
    : type_(type)
{
}
    
Buffer::Ptr HttpRequest::Serialize()
{
    Buffer::Ptr sp_buf = Buffer::MAKE(HTTP_SIZE);

    char content_length[64] = {0};
    
    Buffer::Ptr sp_body;
    
    if (spBody_) {
        sp_body = spBody_->Serialize();
        uint32_t len = sp_body->size();
        sprintf(content_length, "Content-Length: %d\r\n", len);
    }
    
    char* p_buf = (char*)sp_buf->getBuf();
    
    sprintf(p_buf,
            "%s %s HTTP/1.%d\r\n"
            "%s"  // Host if 1.1
            "User-Agent: FuzeTransport\r\n"
            "Connection: Keep-Alive\r\n"
            "%s"  // Content-Length if body included
            "\r\n"
            "%s", // body if available
            toStr(type_),
            requestURI_.c_str(),
            (v11_ ? 1 : 0),
            (v11_ ? "Host:\r\n" : ""), // leaving it empty as it doesn't signify anything
            content_length,
            (sp_body ? (char*)sp_body->getBuf() : ""));
    
    uint32_t len = (uint32_t)strlen(p_buf);
    
    sp_buf->setSize(len);

    return sp_buf;
}

void HttpRequest::Parse(const uint8_t* pMsg, uint32_t msgLen)
{
    // set Method
    type_ = ParseMethodType((char*)pMsg, msgLen);
    
    const char* p = reinterpret_cast<const char*>(pMsg);

    // set Request-URI
    while (*p != ' ') ++p;
    ++p; // pass SP
    const char* p_end = p;
    while (*p_end != ' ') ++p_end;
    requestURI_.assign(p, p_end-p);

    // parse body message
    if (const char* p_value =
            msg::find_header_value(p, "content-length")) {
        int content_length = atoi(p_value);
        
        if (content_length > 0) {
            if (const char* p_body = strstr(p, "\r\n\r\n")) {
                p_body += 2; // we assume \r\n before header name
                if (requestURI_ == Mapping::RESOURCE_NAME) {
                    spBody_.reset(new Mapping);
                    spBody_->Parse((uint8_t*)p_body,
                                   (uint32_t)strlen(p_body));
                }
            }
        }
    }
}

void HttpRequest::SetRequestURI(const string& rReqURI)
{
    requestURI_ = rReqURI;
}

void HttpRequest::SetMethodType(HttpRequest::Type type)
{
    type_ = type;
}

const string& HttpRequest::GetRequestURI()
{
    return requestURI_;
}
    
HttpRequest::Type HttpRequest::GetMethodType()
{
    return type_;
}

HttpRequest::Type HttpRequest::ParseMethodType(char* pBuf, uint32_t len)
{
    HttpRequest::Type type = INVALID;
    
    switch (*pBuf)
    {
        case 'C':
            if ((len >= 7) && (memcmp(pBuf, "CONNECT", 7) == 0)) {
                type = CONNECT;
            }
            break;
        case 'G':
            if ((len >= 3) && (memcmp(pBuf, "GET", 3) == 0)) {
                type = GET;
            }
            break;
        case 'P':
            if ((len >= 3) && (memcmp(pBuf, "PUT", 3) == 0)) {
                type = PUT;
            }
            else if ((len >= 4) && (memcmp(pBuf, "POST", 4) == 0)) {
                type = POST;
            }
            break;
        default:;
    }
    
    return type;
}
    
    
HttpResponse::HttpResponse()
    : responseCode_(300)
{
}

Buffer::Ptr HttpResponse::Serialize()
{
    Buffer::Ptr sp_buf = Buffer::MAKE(HTTP_SIZE);
    
    char* p_buf = (char*)sp_buf->getBuf();
    
    sprintf(p_buf, "HTTP/1.%d %d %s\r\n"
                   "User-Agent: Fuze\r\n"
                   "\r\n",
            (v11_ ? 1 : 0), responseCode_, reason_.c_str());
    uint32_t len = (uint32_t)strlen(p_buf);
    sp_buf->setSize(len);
    
    return sp_buf;
}

void HttpResponse::Parse(const uint8_t* pMsg, uint32_t msgLen)
{
    const char* p_buf = (char*)pMsg + strlen("HTTP/");

    // get version
    if (memcmp(p_buf, "1.1", 3) == 0) {
        v11_ = true;
    }
    
    char code_str[4];
    p_buf += strlen("1.1 ");
    memcpy(code_str, p_buf, 3);
    code_str[3] = 0;
    responseCode_ = atoi(code_str);
}

uint32_t HttpResponse::GetResponseCode()
{
    return responseCode_;
}

void HttpResponse::SetResponseLine(uint32_t code, const char* pReason)
{
    responseCode_ = code;
    reason_       = pReason;
}

string HttpResponse::GetReason()
{
    return reason_;
}
    
} // namespace tp
} // namespace fuze
