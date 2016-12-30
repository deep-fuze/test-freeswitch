//
//  Address.h
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#ifndef Address_h
#define Address_h

#include <event2/event.h>
#include <string>

#ifdef __ANDROID_API__
#include <netinet/in.h>
#endif


using std::string;

namespace fuze {

//
// Simple Address structure for convenience
//
class Address
{
public:
    Address() { Clear(); }
    Address(const sockaddr_in& rAddr) { addr_ = rAddr; }
    
    bool     operator==(const Address& rAddress) const
    {
        return (addr_.sin_addr.s_addr == rAddress.addr_.sin_addr.s_addr) &&
               (addr_.sin_port == rAddress.addr_.sin_port);
    }
    bool     operator!=(const Address& rAddress) const {return !(*this == rAddress);}
    Address& operator=(const Address& rAddress)
    {
        addr_ = rAddress.addr_;
        return *this;
    }
    
    string       IPString() const;
    in_addr      IPNum() const { return addr_.sin_addr; } // network byte ordered
    uint16_t     Port() const { return ntohs(addr_.sin_port); }  // host byte ordered
    sockaddr_in  SocketAddress() const { return addr_; }
    
    bool Valid() const {return (addr_.sin_addr.s_addr != INADDR_NONE && addr_.sin_port != 0);}
    void Clear();
    
    // return false if pIP is not valid
    bool SetIP(const char* pIP);
    bool SetPort(uint16_t port);
    void SetSockAddr(const sockaddr_in& rSockAddr) {addr_ = rSockAddr;}
    
private:
    sockaddr_in  addr_;
};

class DebugOut;
DebugOut& operator<<(DebugOut& rOut, const Address& rAddr);

// helper method
string toStr(const in_addr& addr);    
    
} // namespace fuze

#endif /* Address_hpp */
