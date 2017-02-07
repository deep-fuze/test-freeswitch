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
        if (rAddr.IPType() == AF_INET6) rOut << "[";
        rOut << rAddr.IPString();
        if (rAddr.IPType() == AF_INET6) rOut << "]";
        rOut << ":" << rAddr.Port();
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

Address::Address()
{
    Clear();
}

Address::Address(const sockaddr_storage& rAddr)
{
    if (rAddr.ss_family == AF_INET) {
        addr_.sa4 = reinterpret_cast<const sockaddr_in&>(rAddr);
    }
    else if (rAddr.ss_family == AF_INET6) {
        addr_.sa6 = reinterpret_cast<const sockaddr_in6&>(rAddr);
    }
}
    
bool Address::operator==(const Address& rAddress) const
{
    if (addr_.sa.sa_family == rAddress.addr_.sa.sa_family) {
        if (addr_.sa.sa_family == AF_INET) {
            return (addr_.sa4.sin_addr.s_addr == rAddress.addr_.sa4.sin_addr.s_addr &&
                    addr_.sa4.sin_port == rAddress.addr_.sa4.sin_port);
        }
        else if (addr_.sa.sa_family == AF_INET6) {
            return (memcmp(&addr_.sa6.sin6_addr,
                           &rAddress.addr_.sa6.sin6_addr, sizeof(in6_addr)) == 0 &&
                    (addr_.sa6.sin6_port == rAddress.addr_.sa6.sin6_port));
        }
    }
    
    return false;
}

bool Address::operator!=(const Address& rAddress) const
{
    return !(*this == rAddress);
}
    
Address& Address::operator=(const Address& rAddress)
{
    addr_ = rAddress.addr_;
    return *this;
}
    
void Address::Clear()
{
    memset(&addr_, 0, sizeof(addr_));
    addr_.sa4.sin_family = AF_INET;
    addr_.sa4.sin_addr.s_addr = INADDR_NONE;
}

bool Address::Valid() const
{
    if (addr_.sa.sa_family == AF_INET) {
        return (addr_.sa4.sin_addr.s_addr != INADDR_NONE && addr_.sa4.sin_port != 0);
    }
    
    return true;
}

int Address::SockAddrLen() const
{
    return (addr_.sa.sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
}
    
string Address::IPString() const
{
    char buf[INET6_ADDRSTRLEN] = {0};
    
    if (addr_.sa.sa_family == AF_INET) {
        evutil_inet_ntop(AF_INET, &addr_.sa4.sin_addr, buf, INET6_ADDRSTRLEN);
    }
    else {
        evutil_inet_ntop(AF_INET6, &addr_.sa6.sin6_addr, buf, INET6_ADDRSTRLEN);
    }

    return buf;
}

bool Address::SetPort(uint16_t port)
{
    bool result = false;
    
    if (port > 0) {
        addr_.sa4.sin_port = htons(port);
        result = true;
    }
    
    return result;
}

bool Address::SetIP(const char* pIP)
{
    bool result = false;

    if (!pIP) {
        SetIPv4AnyAddress();
        return true;
    }

    int family = GetIPType(pIP);
    
    if (family == AF_INET) {
        if (evutil_inet_pton(AF_INET, pIP, &addr_.sa4.sin_addr) == 1) {
            addr_.sa4.sin_family = AF_INET;
            result = true;
        }
    }
    else if (family == AF_INET6) {
        if (evutil_inet_pton(AF_INET6, pIP, &addr_.sa6.sin6_addr) == 1) {
            addr_.sa6.sin6_family = AF_INET6;
            result = true;
        }
    }
    
    return result;
}
    
void Address::SetIPv4AnyAddress()
{
    addr_.sa4.sin_family      = AF_INET;
    addr_.sa4.sin_addr.s_addr = INADDR_ANY;
}
    
void Address::SetIPv6AnyAddress()
{
    addr_.sa6.sin6_family = AF_INET6;
    addr_.sa6.sin6_addr   = IN6ADDR_ANY_INIT;
}

bool Address::IsIPv4() const
{
    return (addr_.sa.sa_family == AF_INET);
}
    
bool Address::IsIPv6() const
{
    return (addr_.sa.sa_family == AF_INET6);
}
    
int Address::IPType() const
{
    return addr_.sa.sa_family;
}
    
} // namespace fuze
