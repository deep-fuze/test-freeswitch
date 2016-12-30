//
//  Transport.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ProxyConnector.h>
#include <MutexLock.h>
#include <openssl/md5.h>
#include <Server.h>

#ifdef WIN32
#include <WinDNS.h> // trying cache bypass
#include <Iphlpapi.h>
#else
#include <net/if.h>
#include <string.h>
#ifndef __ANDROID_API__
#include <ifaddrs.h>
#endif
#endif

#include <algorithm>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

Transport* Transport::GetInstance()
{
    return TransportImpl::GetInstance();
}
    
Transport::Transport()
{
}

void Transport::EnableFuzeLog()
{
    dout().EnableFuzeLog();
}
    
const char* toStr(TransportBase::Type eType)
{
    switch (eType)
    {
    case TransportBase::NONE:          return "None";
    case TransportBase::AUDIO:         return "Audio";
    case TransportBase::VIDEO:         return "Video";
    case TransportBase::SCREEN_SHARE:  return "ScreenShare";
    default:                           return "Invalid";
    }
}
    
TransportBase::Type GetSrcBaseType(const CongestionInfo& rInfo)
{
    TransportBase::Type src_type = TransportBase::NONE;
    
    CongestionInfo::const_iterator it
        = rInfo.find(SRC_BASE_TYPE);

    if (it != rInfo.end()) {
        
        const string& r_src = it->second;
        
        if (r_src == toStr(TransportBase::AUDIO)) {
            src_type = TransportBase::AUDIO;
        }
        else if (r_src == toStr(TransportBase::VIDEO)) {
            src_type = TransportBase::VIDEO;
        }
        else if (r_src == toStr(TransportBase::SCREEN_SHARE)) {
            src_type = TransportBase::SCREEN_SHARE;
        }
        else {
            ELOG("Unknown base type: " << r_src);
        }
    }
    else {
        ELOG("Source base type is not set!");
    }
    
    return src_type;
}
    
NetworkBuffer::NetworkBuffer(uint32_t size)
    : Buffer(size)
    , remotePort_(0)
    , changed_(false)
    , appID_(INVALID_ID)
    , bShallowCopy_(false)
{
}
    
NetworkBuffer::NetworkBuffer(Buffer::Ptr spRecv)
    : Buffer(*spRecv)
    , remotePort_(0)
    , changed_(false)
    , appID_(INVALID_ID)
    , bShallowCopy_(true)
{
}

namespace proxy {

const char* toStr(Type type)
{
    switch (type)
    {
    case NONE:  return "";
    case HTTP:  return "HTTP";
    case SOCKS: return "SOCKS";
    default:    return "INVALID";
    }
}
    
void SetInfo(const char* pProxyAddress,
             const char* pCredential,
             Type        type)
{
    MLOG("Proxy: " << (pProxyAddress ? pProxyAddress : " N/A"));
    
    bool enable = (pProxyAddress && (*pProxyAddress != 0));

#ifdef FORCE_HTTP_PROXY
    if (!enable) return;
#endif
    
    TransportImpl::GetInstance()->EnableProxyConnector(enable);
    
    if (ProxyConnector::Ptr sp_proxy =
        TransportImpl::GetInstance()->GetProxyConnector()) {
        sp_proxy->SetProxyInfo(pProxyAddress, pCredential, type);
    }
}

void GetInfo(string& rProxy,
             string& rCrednetial,
             Type&   rType)
{
    if (ProxyConnector::Ptr sp_proxy =
        TransportImpl::GetInstance()->GetProxyConnector()) {
        rProxy      = sp_proxy->GetProxyAddress();
        rType       = sp_proxy->GetProxyType();
        rCrednetial = sp_proxy->GetUserCredential();
    }
}
    
} // namespace proxy
    
string GetLocalIPAddress(const char* pRemoteAddr)
{
    string ip_addr;

    // by using UDP connect, we can find out the best outgoing
    // network interface without actually connecting far end
    // use Remote IP address to know what network
    // interface is used by local routing table
    evutil_socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock != INVALID_SOCKET) {
        // we connect the address specified
        Address remote;
        remote.SetIP(pRemoteAddr);
        remote.SetPort(53); // DNS port but can be anything
        sockaddr_in addr = remote.SocketAddress();        

        if (connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in)) == 0) {
            sockaddr_in  local;
            ev_socklen_t len = sizeof(local);
            if (getsockname(sock, (sockaddr*)&local, &len) == 0) {
                static in_addr s_last_val = {0};
                if (memcmp(&s_last_val, &local.sin_addr, sizeof(in_addr))) {
                    if (strcmp(pRemoteAddr, "8.8.8.8") == 0) {
                        MLOG(toStr(s_last_val) << " -> " << toStr(local.sin_addr));
                        s_last_val = local.sin_addr;
                    }
                    else {
                        MLOG("Found IP " << toStr(local.sin_addr) <<
                             " with respect to remote IP " << pRemoteAddr <<
                             " (current local IP: " << toStr(s_last_val) << ")");
                    }
                }
                ip_addr = toStr(local.sin_addr);
            }
            else {
                ELOG("getsockname failed");
            }
        }
        else { // should we use real TCP connect.. if it fails agian?
#ifdef WIN32 // MQT-2516
			const IPAddr dest_ip = inet_addr(pRemoteAddr);
			if (INADDR_NONE != dest_ip) {
				DWORD if_index = 0;
				if (GetBestInterface(dest_ip, &if_index) == NO_ERROR) {
					std::vector<char> ip_table(sizeof(MIB_IPADDRTABLE));
					ULONG ip_table_len = ip_table.size();
					MIB_IPADDRTABLE* p_mib = reinterpret_cast<MIB_IPADDRTABLE*>(&ip_table[0]);
					if (GetIpAddrTable(p_mib, &ip_table_len, false) 
							== ERROR_INSUFFICIENT_BUFFER) {
						ip_table.resize(ip_table_len);
					}

					if (GetIpAddrTable(p_mib, &ip_table_len, false) == NO_ERROR) {									   						
						for (DWORD i = 0; i < p_mib->dwNumEntries; ++i) {
							if (p_mib->table[i].dwIndex == if_index) {
								in_addr* p_addr = (in_addr *)&(p_mib->table[i].dwAddr);
								if (const char* p_ip = inet_ntoa(*p_addr)) {
									MLOG(p_ip << " using best interface #" << if_index);
									ip_addr = p_ip;
									break;
								}
							}
						}
					}
				}
			}
#endif
			if (ip_addr.empty()) {
				int e = evutil_socket_geterror(sock);
				ELOG("Failed connect() to " << remote << " (" <<
					evutil_socket_error_to_string(e) << ')');
			}
        }
        
        evutil_closesocket(sock);
    }
    else {
        ELOG("Failed to create socket")
    }
    
    return ip_addr;
}
    
bool IsThisIP(const char* pAddress)
{
    Address addr;
    return addr.SetIP(pAddress);
}

uint32_t GetIPNumber(const char* pIP)
{
    Address addr;
    if (addr.SetIP(pIP)) {
        return addr.IPNum().s_addr;
    }
    
    return 0;
}
    
vector<string> GetAddrInfo(const string& rAddress)
{
    vector<string> result;

    Address addr;
    if (addr.SetIP(rAddress.c_str())) {
        MLOG("Given domain is IP address: " << rAddress);
        result.push_back(rAddress);
    }
    else {
        addrinfo* ai = 0;
        int res = getaddrinfo(rAddress.c_str(), 0, 0, &ai);
        if (res == 0) {
            for (addrinfo* p = ai; p != 0; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN];
                    sockaddr_in* sin = (sockaddr_in*)p->ai_addr;
                    if (evutil_inet_ntop(AF_INET, &sin->sin_addr, 
                                         buf, INET_ADDRSTRLEN)) {                                         
                        if (std::find(result.begin(), result.end(), buf)
                                == result.end()) {
                            MLOG("Address " << rAddress << 
                                 " resolved to " << buf);                                 
                            result.push_back(buf);
                        }
                    }
                }
            }
            
            if (ai) {
                freeaddrinfo(ai);
            }
        }
        else {
            // not sure bu gai_strerror wasn't work some times.
            const char* p = "unknown";
            switch (res)
            {
            case EAI_AGAIN:    p = "temporary failure in name resolution"; break;
            case EAI_BADFLAGS: p = "invalid value for ai_flags"; break;
            case EAI_FAIL:     p = "non-recoverable failure in name resolution"; break;
            case EAI_FAMILY:   p = "ai_family not supported"; break;
            case EAI_MEMORY:   p = "memory allocation failure"; break;
            case EAI_NONAME:   p = "hostname or servname not provided, or not known"; break;
            case EAI_SERVICE:  p = "servname not supported for ai_socktype"; break;
            case EAI_SOCKTYPE: p = "ai_socktype not supported"; break;
            default:;
            }            
#ifndef WIN32
            ELOG("Domain: " << rAddress << " (Error: " << res << ") [" <<
                 gai_strerror(res) << "] " << p);
#else
            // for windows DNS cache seems to be returning error such as WSANO_DATA
            // try DnsQuery API with no cache use in this case
            WLOG("Domain: " << rAddress << " (Error: " << res << ") [" <<
                 gai_strerrorA(res) << "] " << p);
            DNS_RECORD* p_rec = 0;
            DNS_STATUS res = DnsQuery_A(rAddress.c_str(), DNS_TYPE_A,
                                        DNS_QUERY_BYPASS_CACHE, 0, &p_rec, 0);
            if (!res) {
                IN_ADDR in_addr;
                char ip_buf[INET_ADDRSTRLEN];
                for (DNS_RECORD* p_a = p_rec; p_a != 0; p_a = p_a->pNext) {
                    in_addr.S_un.S_addr = p_a->Data.A.IpAddress;
                    if (evutil_inet_ntop(AF_INET, &in_addr, 
                                         ip_buf, INET_ADDRSTRLEN)) {
                        if (std::find(result.begin(), result.end(), ip_buf)
                                == result.end()) {
                            MLOG("Address " << rAddress <<
                                 " resolved by DnsQuery to " << ip_buf);
                            result.push_back(ip_buf);
                        }
                    }
                }
            }
            else {
                ELOG("DnsQuery failed again: " << res);
            }
            if (p_rec) {
                DnsRecordListFree(p_rec, DnsFreeRecordListDeep);
            }
#endif
        }
    }
    
    return result;
}
    
vector<string> TranslateToIPs(const string& rAddress)
{
    vector<string> result;
    
    Resolver::Ptr sp_res = Resolver::Create();
    sp_res->SetQuery(rAddress, Record::A);
    for (auto& rec : sp_res->Query()) {
        if (A::Ptr sp_a = fuze_dynamic_pointer_cast<A>(rec)) {
            if (sp_a->hostName_.empty() == false) {
                MLOG("Address " << rAddress << " resolved to " << sp_a->hostName_);
                result.push_back(sp_a->hostName_);
            }
        }
    }
    
    if (result.empty()) {
        WLOG("c-ares failed - try getaddrinfo");
        result = GetAddrInfo(rAddress);
    }
    
    return result;
}
    
string TranslateToIP(const string& rAddress)
{
    // check if this is valid IP already
    Address addr;
    if (addr.SetIP(rAddress.c_str())) {
        return rAddress;
    }
   
    const vector<string>& ip_addrs = TranslateToIPs(rAddress);
    
    if (!ip_addrs.empty()) {
        return ip_addrs[0];
    }
    
    return "";
}

void dns::MarkAsBadCache(const string& rAddress)
{
    TransportImpl::GetInstance()->MarkDnsCacheBad(rAddress);
}
    
void dns::ClearCache()
{
    TransportImpl::GetInstance()->ClearDnsCache();
}
    
bool ReservePort(bool bUDP, uint16_t port, const char* pIP, uint32_t holdTime, bool logError)
{
    bool bResult = false;
    
    evutil_socket_t sock = INVALID_SOCKET;

    if (bUDP) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    else {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    
    if (sock != INVALID_SOCKET) {
        
        in_addr ip_addr;
        ip_addr.s_addr = INADDR_ANY;
        
        if (pIP) {
            evutil_inet_pton(AF_INET, pIP, &ip_addr);
        }
        
        sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        
        saddr.sin_family = AF_INET;
        saddr.sin_port   = htons(port);
        saddr.sin_addr   = ip_addr;
        
        if (::bind(sock, (sockaddr*)&saddr, sizeof(saddr)) == 0) {
            bResult = true;
        }
        else {
            if (logError)
            {
                DLOG("Failed to bind to \"" << pIP << ":" << port << "\"");
            }
        }
        
        if (bResult && bUDP) {
            if (holdTime == 0) {
                evutil_closesocket(sock);
            }
            else {
                TransportImpl::GetInstance()->ReserveUdpPort(port, sock, holdTime);
            }
        }
        else {
            evutil_closesocket(sock);
        }
    }
    else {
        ELOG("Failed to create socket!!");
    }
    
    return bResult;
}
    
bool IsUdpPortAvailable(uint16_t port, const char* pIP)
{
    return ReservePort(true, port, pIP, 0, false);
}

bool IsTcpPortAvailable(uint16_t port, const char* pIP)
{
    return ReservePort(false, port, pIP, 0, false);
}

bool ReserveUdpPort(uint32_t holdTimeMs, uint16_t port, const char* pIP)
{
    return ReservePort(true, port, pIP, holdTimeMs, true);
}
    
void ReleaseUdpPort(uint16_t port)
{
    if (PortReserve::Ptr sp_rsv
            = TransportImpl::GetInstance()->GetReservedPort(port)) {
        _MLOG_(port << " (s:" << sp_rsv->sock_ << ")");
        StopTimer(sp_rsv, sp_rsv->timerID_);
        evutil_closesocket(sp_rsv->sock_);
    }
}

void HashByMD5(uint8_t* pBuf, uint32_t bufLen, uint8_t* digest)
{
    MD5(pBuf, bufLen, digest);
}

string MD5Hex(uint8_t* digest)
{
    char md5_str[MD5_DIGEST_LENGTH*3] = {0};
    
    for(uint32_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5_str+(i*2), "%02x", digest[i]);
    }
    
    return md5_str;
}
    
const char* toStr(TransportUser::Type type)
{
    switch (type)
    {
    case TransportUser::FUZE_SIP:          return "FuzeSip";
    case TransportUser::FUZE_SIP_RSR_MGR:  return "SipResourceMgr";
    case TransportUser::TRANSPORT_RSR_MGR: return "TransportResourceMgr";
    default:                               return "INVALID";
    }
}
    
const char* toStr(EventType type)
{
    switch (type)
    {
    case ET_CONNECTED:     return "CONNECTED";
    case ET_DISCONNECTED:  return "DISCONNECTED";
    case ET_REFUSED:       return "REFUSED";
    case ET_FAILED:        return "FAILED";
    case ET_IN_PROGRESS:   return "IN PROGRESS";
    case ET_APP_DELAY:     return "APP DELAY";
    default:               return "NONE";
    }
}

const char* toStr(ConnectionType eType)
{
    switch (eType)
    {
    case CT_UDP:             return "UDP";
    case CT_TCP:             return "TCP";
    case CT_TCP_LISTENER:    return "TCP Listener";
    case CT_TLS:             return "TLS";
    case CT_DTLS_CLIENT:     return "DTLS Client";
    case CT_DTLS_SERVER:     return "DTLS Server";
    case CT_DTLS_TYPE:       return "DTLS TYPE";
    case CT_DGRAM_TYPE:      return "DGRAM TYPE";
    case CT_STREAM_TYPE:     return "STREAM TYPE";
    default:                 return "INVALID";
    }
}
    
const char* toStr(RateType type)
{
    switch (type)
    {
    case RT_LOCAL_SEND:  return "Local Send";
    case RT_LOCAL_RECV:  return "Local Recv";
    case RT_REMOTE_SEND: return "Remote Send";
    case RT_REMOTE_RECV: return "Remote Recv";
    default:             return "INVALID";
    }
}

int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line)
{
    TimerService::Ptr& sp_ts = TransportImpl::GetInstance()->GetTimerService();
    return sp_ts->StartTimerEx(pTimer, ms, appData, pFile, line);
}
    
int64_t StartTimerEx(Timer* pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line)
{
    TimerService::Ptr& sp_ts = TransportImpl::GetInstance()->GetTimerService();
    return sp_ts->StartTimerEx(pTimer, ms, appData, pFile, line);
}

int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, void* appData,
                     const char* pFile, int line)
{
    TimerService::Ptr& sp_ts = TransportImpl::GetInstance()->GetTimerService();
    return sp_ts->StartTimerEx(pTimer, ms, appData, pFile, line);
}

void StopTimer(Timer::Ptr pTimer, int64_t handle)
{
    TimerService::Ptr& sp_ts = TransportImpl::GetInstance()->GetTimerService();
    return sp_ts->StopTimer(pTimer, handle);
}
    
void StopTimer(Timer* pTimer, int64_t handle)
{
    TimerService::Ptr& sp_ts = TransportImpl::GetInstance()->GetTimerService();
    return sp_ts->StopTimer(pTimer, handle);
}
    
namespace dns {
    
bool Record::operator==(const Record& rRhs)
{
    bool result = false;
    
    if (domain_ == rRhs.domain_ && type_ == rRhs.type_) {
        switch (type_)
        {
        case Record::A:
        {
            struct A* p_lhs = dynamic_cast<struct A*>(this);
            const struct A* p_rhs = dynamic_cast<const struct A*>(&rRhs);
            if (p_lhs && p_rhs) {
                if (p_lhs->hostName_ == p_rhs->hostName_) {
                    result = true;
                }
            }
            break;
        }
        case Record::SRV:
        {
            struct SRV* p_lhs = dynamic_cast<struct SRV*>(this);
            const struct SRV* p_rhs = dynamic_cast<const struct SRV*>(&rRhs);
            if (p_lhs && p_rhs) {
                if (p_lhs->name_ == p_rhs->name_ && p_lhs->port_ == p_rhs->port_) {
                    result = true;
                }
            }
            break;
        }
        case Record::NAPTR:
        {
            struct NAPTR* p_lhs = dynamic_cast<struct NAPTR*>(this);
            const struct NAPTR* p_rhs = dynamic_cast<const struct NAPTR*>(&rRhs);
            if (p_lhs && p_rhs) {
                if (p_lhs->replacement_ == p_rhs->replacement_) {
                    result = true;
                }
            }
            break;
        }
        default:;
        }
    }
    
    return result;
}
    
const char* toStr(Record::Type type)
{
    switch (type)
    {
    case Record::A:     return "A";
    case Record::SRV:   return "SRV";
    case Record::NAPTR: return "NAPTR";
    default:            return "INVALID";
    }
}
    
} // namespace dns

DebugOut& operator<<(DebugOut& rOut, dns::Record::Ptr spRecord)
{
    switch (spRecord->type_)
    {
    case dns::Record::A:
        if (A::Ptr sp = fuze_dynamic_pointer_cast<A>(spRecord)) {
            rOut << "[A] " << sp->domain_ << " -> " << sp->hostName_ << " ttl " << sp->ttl_;
        }
        break;
    case dns::Record::SRV:
        if (SRV::Ptr sp = fuze_dynamic_pointer_cast<SRV>(spRecord)) {
            rOut << "[SRV] " << sp->name_ << ":" << sp->port_ << " ttl " << sp->ttl_
                 << " priority: " << sp->priority_ << " weight: " << sp->weight_;
        }
        break;
    case dns::Record::NAPTR:
        if (NAPTR::Ptr sp = fuze_dynamic_pointer_cast<NAPTR>(spRecord)) {
            rOut << "[NAPTR] " << sp->replacement_ << " ttl " << sp->ttl_ << " "
                 << sp->flag_ << " " << sp->services_ << " order: " << sp->order_
                 << ", pref: " << sp->pref_ << " " << sp->regexp_;
        }
        break;
    default:;
    }
    
    return rOut;
}
    
} // namespace fuze
