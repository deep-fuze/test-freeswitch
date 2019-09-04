//
//  Mapping.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/13/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Mapping.h>
#include <Log.h>

#ifdef __linux__
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Mapping::" << __FUZE_FUNC__ << ": " << B)

namespace fuze {
 
const char* Mapping::RESOURCE_NAME = "/fuze/mapping";
    
Mapping::Mapping()
    : conn_(CT_INVALID)
    , port_(0)
    , id_("none")
{
    type_ = MsgBody::MAP;
}
    
Mapping::Mapping(ConnectionType type, string ip, uint16_t port)
    : conn_(type)
    , ipStr_(ip)
    , port_(port)
    , id_("none")
{
    type_ = MsgBody::MAP;
}

Buffer::Ptr Mapping::Serialize()
{
    Buffer::Ptr sp_buf = Buffer::MAKE(1000);

    string map_info = Transport::GetInstance()->GetMappingInfo();
    
    char* p_buf = (char*)sp_buf->getBuf();
    sprintf(p_buf,
            "CONNECTION:%s\r\n"
            "IP:%s\r\n"
            "PORT:%hu\r\n"
            "ID:%s\r\n"
            "INFO:%s\r\n"
            "\r\n",
            toStr(conn_), ipStr_.c_str(), port_,
            id_.c_str(), map_info.c_str());
    
    uint32_t len = (uint32_t)strlen(p_buf);
    sp_buf->setSize(len);
    
    return sp_buf;
}

void Mapping::Parse(const uint8_t* pMsg, uint32_t msgLen)
{
    const char* p = reinterpret_cast<const char*>(pMsg);
    
    if (const char* p_value =
            msg::find_header_value(p, "CONNECTION")) {
        
        if (strncmp(p_value, "UDP", 3) == 0) {
            conn_ = CT_UDP;
        }
        else if (strncmp(p_value, "TCP", 3) == 0) {
            // we are mapping into listener
            // as listener will register binding
            conn_ = CT_TCP_LISTENER;
        }
        else {
            WLOG("Unknown value: " << p_value);
        }
    }

    if (const char* p_value =
            msg::find_header_value(p, "IP")) {
        if (const char* p_end = strstr(p_value , "\r\n")) {
            ipStr_.assign(p_value, p_end - p_value);
        }
    }
    
    if (const char* p_value =
            msg::find_header_value(p, "PORT")) {
        port_ = atoi(p_value);
    }
}
    
void Mapping::SetConnType(ConnectionType type)
{
    conn_ = type;
}
    
void Mapping::SetIP(string ip)
{
    ipStr_ = ip;
}
    
void Mapping::SetPort(uint16_t port)
{
    port_ = port;
}

void Mapping::SetID(const string& rID)
{
    if (!rID.empty()) {
        id_ = rID;
    }
}
    
} // namespace fuze
