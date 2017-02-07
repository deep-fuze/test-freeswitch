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
    Address();
    Address(const sockaddr_storage& rAddr);
    
    bool     operator==(const Address& rAddress) const;
    bool     operator!=(const Address& rAddress) const;
    Address& operator=(const Address& rAddress);
    
    string    IPString() const;
    in_addr   IPNum() const { return addr_.sa4.sin_addr; } // network byte ordered
    uint16_t  Port() const  { return ntohs(addr_.sa4.sin_port); } // host byte ordered
    
    const sockaddr* SockAddr() const { return &(addr_.sa); }
    int             SockAddrLen() const;
    
    bool Valid() const;
    void Clear();
    
    // return false if pIP is not valid
    bool SetIP(const char* pIP);
    bool SetPort(uint16_t port);
    
    void SetIPv4AnyAddress();
    void SetIPv6AnyAddress();
    
    bool IsIPv4() const;
    bool IsIPv6() const;
    int  IPType() const;
    
private:
    
    union {
        sockaddr     sa;
        sockaddr_in  sa4;
        sockaddr_in6 sa6;
    } addr_;
};

class DebugOut;
DebugOut& operator<<(DebugOut& rOut, const Address& rAddr);

// helper method
string toStr(const in_addr& addr);    
    
} // namespace fuze

#endif /* Address_hpp */
