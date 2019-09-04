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
    Address(const sockaddr_in& rAddr);
    
    bool     operator==(const Address& rAddress) const;
    bool     operator!=(const Address& rAddress) const;
    Address& operator=(const Address& rAddress);
    
    string       IPString() const;
    in_addr      IPNum() const; // network byte ordered
    uint16_t     Port() const;  // host byte ordered
    sockaddr_in  SocketAddress() const;
    
    bool Valid() const;
    void Clear();
    
    // return false if pIP is not valid
    bool SetIP(const char* pIP);
    bool SetPort(uint16_t port);
    void SetSockAddr(const sockaddr_in& rSockAddr);
    
private:
    sockaddr_in  addr_;
};

class DebugOut;
DebugOut& operator<<(DebugOut& rOut, const Address& rAddr);

// helper method
string toStr(const in_addr& addr);    
    
} // namespace fuze

#endif /* Address_hpp */
