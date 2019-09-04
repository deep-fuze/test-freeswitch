//
//  Mapping.h
//  FuzeTransport
//
//  Created by Tim Na on 1/13/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__Mapping__
#define __FuzeTransport__Mapping__

#include <HTTP.h>

namespace fuze {
    
class Mapping : public MsgBody
{
public:
    typedef fuze_shared_ptr<Mapping> Ptr;
    
    static const char* RESOURCE_NAME;
    
    Mapping();
    Mapping(ConnectionType type, string ip, uint16_t port);
    
    // Implement ByteStream
    virtual Buffer::Ptr Serialize();
    virtual void        Parse(const uint8_t* pMsg, uint32_t msgLen);
    
    virtual Type GetType() { return MAP; }
    
    void SetConnType(ConnectionType type);
    void SetIP(string ip);
    void SetPort(uint16_t port);
    void SetID(const string& rID);
    
    ConnectionType ConnType() { return conn_; }
    string         IP()       { return ipStr_;    }
    uint16_t       Port()     { return port_;  }
    
private:
    ConnectionType  conn_;
    string          ipStr_;
    uint16_t        port_;
    string          id_;
};
        
} // namespace fuze

#endif /* defined(__FuzeTransport__Mapping__) */
