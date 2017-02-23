//
//  Util.h
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef Util_h
#define Util_h

namespace fuze {
    
namespace proxy {
    
enum Type { NONE, HTTP, SOCKS };

const char* toStr(Type type);

// set Proxy Info for proxy traversal
//
//   Address in form of "IP:Port"
//   Authentication in form of "username:password"
//
void SetInfo(const char*  pProxyAddres,
             const char*  pCredential,
             Type         type);

// get Proxy Info - interim solution for legacy RTP Proxy
//
void GetInfo(string& rProxy,
             string& rCrednetial,
             Type&   rType);
    
} // namespace proxy
    
//-----------------------------------------------------------------------------
// helper method
//-----------------------------------------------------------------------------
//
// Return empty string when local IP address is not
// available yet due to network change
//
// by default use google's public 8.8.8.8 as remote address to connect
string    GetLocalIPAddress(const char* pRemoteAddr = 0);

// Check whether this is IP address or domain
bool      IsThisIP(const char* pAddress);
bool      IsIPv6OnlyNetwork();
bool      IsIPv4(const char* pIP);
bool      IsIPv6(const char* pIP);
int       GetIPType(const char* pIP); // AF_INET/AF_INET6
uint32_t  GetIPNumber(const char* pIP);

// Apple specific interface for converting IPv4 literal to IPv6 address
string    IPv4toIPv6(const string& rIPv4);

//
// checking the port can be binded or not
// if pIP is 0, then INADDR_ANY is used to test
//
bool      IsUdpPortAvailable(uint16_t port, const char* pIP = 0);
bool      IsTcpPortAvailable(uint16_t port, const char* pIP = 0);

//
// Reserve a UDP port for later use upto given holdTime in milliseconds
// if application doesn't use the port, it will be released after that time
//
bool      ReserveUdpPort(uint32_t holdTimeMs, uint16_t port, const char* pIP = 0);
void      ReleaseUdpPort(uint16_t port);

//
// Get current time in milliseconds using platform API for performance
//
int64_t   GetTimeMs();

//
// Hash by MD5
//
void      HashByMD5(uint8_t* pBuf, uint32_t bufLen, uint8_t* digest);
string    MD5Hex(uint8_t* digest);
    
} // namespace fuze


#endif /* Util_h */
