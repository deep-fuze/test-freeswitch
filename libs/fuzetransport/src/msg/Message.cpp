//
//  Message.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/13/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Message.h>
#include <Mapping.h>
#include <Data.h>
#include <HTTP.h>

#include <Log.h>

#ifdef __linux__
#include <arpa/inet.h>  // ntohl..
#include <string.h>     // memcpy
#include <stdlib.h>
#endif

#ifdef WIN32
#include <WinSock2.h>
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Message::" << __FUZE_FUNC__ << ": " << B)

namespace fuze {
    
const char* toStr(msg::Type type)
{
    switch (type)
    {
        case msg::FUZE: return "FUZE";
        case msg::HTTP: return "HTTP";
        case msg::TLS:  return "TLS";
        default:        return "INVALID";
    }
}
    
namespace msg {
    
    Type get_type(uint8_t* pBuf, uint32_t bufLen)
    {
        if (!pBuf || !bufLen) {
            ELOG("input error");
            return INVALID;
        }
        
        Type msg_type = INVALID;
        
        if (is_fuze_data(pBuf[0])) {
            msg_type = FUZE;
        }
        else if (is_http(pBuf, bufLen)) {
            msg_type = HTTP;
        }
        else if (is_tls(pBuf[0])) {
            msg_type = TLS;
        }
        
        return msg_type;
    }
    
    uint32_t get_length(uint8_t* pBuf, uint32_t bufLen)
    {
        uint32_t msg_len = 0;
        
        if (is_fuze_data(pBuf[0])) {
            // check if we received all the header bytes
            if (bufLen >= Data::FUZE_HEADER_SIZE) {
                uint16_t len = 0;
                memcpy(&len, pBuf+1, sizeof(uint16_t));
                len = ntohs(len) + Data::FUZE_HEADER_SIZE;
                if (len <= bufLen) {
                    msg_len = len;
                }
            }
        }
        else if (is_http(pBuf, bufLen)) {
            // this returns 0 if we don't have entire message
            msg_len = get_http_length(pBuf, bufLen);
            if (msg_len > 0) {
                MLOG("HTTP message (" << bufLen <<
                     "B)\n" << (char*)pBuf);
            }
        }
        else if (is_tls(*pBuf)) {
            if (bufLen >= TlsAppData::TLS_HEADER_SIZE) {
                uint32_t len = get_tls_app_length(pBuf, bufLen);
                if (len <= bufLen) {
                    msg_len = len;
                }
            }
        }
        else {
            ELOG("Unexpected message: " << bufLen <<
                 "B - [Content:" << Hex(pBuf) << "]");
        }
        
        return msg_len;
    }
    
    bool is_fuze_data(uint8_t firstByte)
    {
        return (firstByte == Data::FUZE_MARK);
    }
    
    bool is_http(uint8_t* pFirstByte, uint32_t len)
    {
        return (tp::HttpRequest::ParseMethodType((char*)pFirstByte, len)
                != tp::HttpRequest::INVALID ||
                is_http_response(pFirstByte, len));
    }
    
    bool is_http_response(uint8_t* pFirstByte, uint32_t len)
    {
        return ((len >= 5) && (memcmp(pFirstByte, "HTTP/", 5) == 0));
    }
    
    const char* find_header_value(const char* pMsg, const char* pHeader)
    {
        const char* p = pMsg;
        const char* p_end = p + strlen(p);
        
        while (p < p_end) {
            if (p[0] == '\r' && p[1] == '\n') {
                // compare the first character only to speed up
                if (p[2] == tolower(*pHeader) || p[2] == toupper(*pHeader)) {
                    if (strncasecmp(p+2, pHeader, strlen(pHeader)) == 0) {
                        while (*p != ':') {
                            if (++p >= p_end) return 0;
                        }
                        p++; // pass ':'
                        while (*p == ' ' || *p == '\t') {
                            if (++p >= p_end) return 0;
                        }
                        // here is the pointer to the header value start
                        return p;
                    }
                }
                else if (p[2] == '\r' && p[3] == '\n') {
                    return 0;
                }
            }
            ++p;
        }
        
        return 0;
    }
    
    uint32_t get_http_length(uint8_t* pFirstByte, uint32_t len)
    {
        uint32_t http_length = 0;
        
        const char* p_msg = reinterpret_cast<char*>(pFirstByte);
        
        bool chunked = false;
        int  content_length = 0;
        
        if (const char* p_value =
            find_header_value(p_msg, "Content-Length")) {
            content_length = atoi(p_value);
        }
        else if (const char* p_value =
                 find_header_value(p_msg, "Transfer-Encoding")) {
            if (strncmp(p_value, "chunked", 7) == 0) {
                MLOG("chunked encoding");
                chunked = true;
            }
        }
        
        if (const char* p_body = strstr(p_msg, "\r\n\r\n")) {
            p_body += 4; // CRLF CRLF
            if (chunked) {
                // TODO: for now set it as it is
                http_length = len;
            }
            else {
                // 4 is counting CRLF CRLF
                uint32_t total = uint32_t(p_body-p_msg) + content_length;
                if (total <= len) {
                    http_length = total;
                }
                else {
                    MLOG("Need more data (HTTP:" << total <<
                         "B vs Buf:" << len << "B)");
                }
            }
        }
        
        return http_length;
    }
        
    bool is_tls(uint8_t firstByte)
    {
        bool bResult = true;
        
        switch (firstByte)
        {
            case 20: MLOG("TLS - ChangeCipherSpec"); break;
            case 21: MLOG("TLS - Alert");            break;
            case 22: MLOG("TLS - Handshake")         break;
            case 23: DLOG("TLS - Application");      break;
            default: bResult = false;
        }
        
        return bResult;
    }
    
    // NOTE: this only works for TLS application type
    uint16_t get_tls_app_length(uint8_t* pFirstByte, uint32_t len)
    {
        uint16_t tls_length = 0;
        
        const int TLS_HEADER_SIZE = 5;
        
        if (len >= TLS_HEADER_SIZE) {
            memcpy(&tls_length, pFirstByte+3, sizeof(uint16_t));
            tls_length = ntohs(tls_length);
            tls_length += TLS_HEADER_SIZE;
        }
        
        return tls_length;
    }
    
} // namesapce msg
    
} // namespace fuze
