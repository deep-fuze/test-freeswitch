//
//  Address.cpp
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#include <Address.h>
#include <Log.h>

namespace fuze {

DebugOut& operator<<(DebugOut& rOut, const Address& rAddr)
{
    if (rAddr.Valid()) {
        rOut << rAddr.IPString() << ":" << rAddr.Port();
    }
    else {
        rOut << "empty address";
    }
    
    return rOut;
}

string toStr(const in_addr& addr)
{
    char ip_buf[INET_ADDRSTRLEN] = { "0.0.0.0" };
    if (evutil_inet_ntop(AF_INET, &addr, ip_buf, INET_ADDRSTRLEN)) {
        return ip_buf;
    }
    return string();
}

void Address::Clear()
{
    memset(&addr_, 0, sizeof(addr_));
    addr_.sin_addr.s_addr = INADDR_NONE;
    addr_.sin_family = AF_INET;
}

string Address::IPString() const
{
    char ip_buf[INET_ADDRSTRLEN] = { "0.0.0.0" };
    evutil_inet_ntop(AF_INET, &addr_.sin_addr, ip_buf, INET_ADDRSTRLEN);
    return ip_buf;
}

bool Address::SetPort(uint16_t port)
{
    bool result = false;
    
    if (port > 0) {
        addr_.sin_port = htons(port);
        result = true;
    }
    
    return result;
}

bool Address::SetIP(const char* pIP)
{
    bool result = false;
    
    if (pIP) {
        if (evutil_inet_pton(AF_INET, pIP, &addr_.sin_addr) == 1) {
            result = true;
        }
    }
    
    return result;
}

} // namespace fuze
