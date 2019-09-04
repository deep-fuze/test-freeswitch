//
//  ProxyConnector.cpp
//  FuzeTransport
//
//  Created by Tim Na on 4/4/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <ProxyConnector.h>
#include <TcpTransceiver.h>

#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
#include <curl/curl.h>
#endif

#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
int curl_log_callback(CURL* p, curl_infotype type,
                      char* pLog, size_t len, void* ctx)
{
    if (type == CURLINFO_TEXT && len > 0) {
        _MLOG_(string(pLog, len-1));
    }
    
    return 0;
}
#endif
    
ConnectInfo::ConnectInfo()
    : tcpID_(INVALID_ID)
    , pCurl_(0)
    , socket_(INVALID_SOCKET)
{
}

ConnectInfo::~ConnectInfo()
{
#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
    // the socket belongs to curl, we shouldn't close it on our own
    if (pCurl_) {
        curl_easy_cleanup(pCurl_);
    }
#endif
}
    
ProxyConnector::ProxyConnector()
    : running_(false)
    , connectThread_(this, "ProxyConnector")
{
#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
    connectThread_.Start();
    
    curl_version_info_data* p = curl_version_info(CURLVERSION_NOW);
    MLOG("Age: " << p->age << " Version: " << p->version);
    int feat = p->features;
    if (feat & CURL_VERSION_KERBEROS4)    MLOG("KERBEROS4");
    if (feat & CURL_VERSION_NTLM)         MLOG("NTLM");
    if (feat & CURL_VERSION_GSSNEGOTIATE) MLOG("GSSNEGOTIATE");
    if (feat & CURL_VERSION_SPNEGO)       MLOG("SPNEGO");
    if (feat & CURL_VERSION_SSPI)         MLOG("SSPI");
    if (feat & CURL_VERSION_NTLM_WB)      MLOG("NTLM_WB");
#endif
}

ProxyConnector::~ProxyConnector()
{
    running_ = false;
    
    if (connectThread_.IsRunning()) {
        semaphore_.Post();
        connectThread_.Join();
        MLOG("ProxyConnector thread joined");
    }
}

void ProxyConnector::SetProxyInfo(const char* pProxyAddress,
                                  const char* pCredential,
                                  proxy::Type type)
{
    MLOG(((pProxyAddress && *pProxyAddress) ?
          pProxyAddress : "NO PROXY") << " " << toStr(type) << " (" <<
         ((pCredential && *pCredential) ?
          "***" : "NO") << " CREDENTIAL)");
    
    MutexLock scoped(&strLock_);
    
    if (pProxyAddress) {
        if (proxy_ != pProxyAddress) {
            proxy_ = pProxyAddress;
        }
    }
    else {
        proxy_.clear();
    }
    
    if (pCredential) {
        if (credential_ != pCredential) {
            credential_ = pCredential;
        }
    }
    else {
        credential_.clear();
    }
    
    proxyType_ = type;
}

string ProxyConnector::GetProxyAddress()
{
    MutexLock scoped(&strLock_);
    return proxy_;
}

string ProxyConnector::GetUserCredential()
{
    MutexLock scoped(&strLock_);
    return credential_;
}

proxy::Type ProxyConnector::GetProxyType()
{
    return proxyType_;
}
    
void ProxyConnector::Run()
{
#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
    running_ = true;
    
    while (running_) {
        semaphore_.Wait();
        
        // while we have work to do
        // do the connect work accordingly
        while (ConnectInfo::Ptr sp_info = GetConnectInfo()) {
            
            const string& proxy = GetProxyAddress();
            if (proxy.empty() == false) {
                // try to establish connection through HTTP Proxy
                const char* p_remote = sp_info->remoteAddress_.c_str();
                
                CURL* p = curl_easy_init();
                
                sp_info->pCurl_ = p;
                
                curl_easy_setopt(p, CURLOPT_URL, p_remote);
                curl_easy_setopt(p, CURLOPT_PROXY, proxy.c_str());
                curl_easy_setopt(p, CURLOPT_HTTPPROXYTUNNEL, 1L);
                curl_easy_setopt(p, CURLOPT_FRESH_CONNECT, 1L);
                curl_easy_setopt(p, CURLOPT_CONNECT_ONLY, 1L);
                curl_easy_setopt(p, CURLOPT_PROXYAUTH, CURLAUTH_ANY & ~CURLAUTH_NEGOTIATE);
                curl_easy_setopt(p, CURLOPT_CONNECTTIMEOUT, 30L);
                curl_easy_setopt(p, CURLOPT_VERBOSE, 1L);
                curl_easy_setopt(p, CURLOPT_DEBUGFUNCTION, &curl_log_callback);

#if defined(__ANDROID_API__)
                curl_easy_setopt(p, CURLOPT_NOSIGNAL, 1L);

                // TODO: Tell libcurl the path to our certificate store, so it can validate the certificates.
                // CString castorePath = IApplicationInformation::getInstance()->getPathToCertStorePEMFile();
                // FUZE_LOG_INFO(getLog(), "Path to cert store: %s", castorePath.c_str());
                // curl_easy_setopt(curl, CURLOPT_CAINFO, castorePath.c_str());
                curl_easy_setopt(p, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(p, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

#ifdef WIN32
                // [WIN-2144] Ignore certificate revocation checks on Windows because they can
                // fail intermittently in some customer environments.
                curl_easy_setopt(p, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
#endif

                if (proxyType_ == proxy::SOCKS) {
                    curl_easy_setopt(p, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                }
                
                const string& cred = GetUserCredential();
                if (cred.empty() == false) {
                    curl_easy_setopt(p, CURLOPT_PROXYUSERPWD, cred.c_str());
                } else {
                    // Use the default credentials, if available.  On Windows, this will cause
                    // libcurl to try authenticating with the user's Windows credentials.
                    curl_easy_setopt(p, CURLOPT_PROXYUSERPWD, ":");
                }

                MLOG("Initiating setup connection to " << p_remote <<
                     " through proxy " << proxy << "(" << toStr(proxyType_) << ")");
     
                //
                // CURLE_OK              : succeeded
                // CURLE_COULDNT_CONNECT : proxy address issue
                // CURLE_RECV_ERROR      : username/password issue
                //
                CURLcode ret_code = curl_easy_perform(p);
                if (ret_code == CURLE_OK) {
                    curl_socket_t sock = CURL_SOCKET_BAD;
                    ret_code = curl_easy_getinfo(p, CURLINFO_ACTIVESOCKET, &sock);
                    if (ret_code == CURLE_OK) {
                        sp_info->socket_ = static_cast<evutil_socket_t>(sock);
                        MLOG("Setup succeeded (sock: " << sp_info->socket_ << ")");
                    }
                    else {
                        ELOG("curl_easy_getinfo failed: " << ret_code);
                    }
                }
                else {
                    ELOG("Failed to setup connection: " << ret_code);
                }
            }
            else {
                MLOG("No proxy configured");
            }
            
            // Notify the result
            TransportImpl::GetInstance()->RequestPostConnect(sp_info->tcpID_);
        }
    }
#endif
}

void ProxyConnector::RequestConnection(ConnectInfo::Ptr spInfo)
{
    {
        MutexLock scoped(&qlock_);
        workQ_.push(spInfo);
    }
    
    semaphore_.Post();
}
    
ConnectInfo::Ptr ProxyConnector::GetConnectInfo()
{
    ConnectInfo::Ptr sp_info;
    
    MutexLock scoped(&qlock_);
    
    if (workQ_.empty() == false) {
        sp_info = workQ_.front();
        workQ_.pop();
    }
    
    return sp_info;
}

bool is_http_proxy_available()
{
    bool bResult = false;
    
    if (ProxyConnector::Ptr sp_proxy =
        TransportImpl::GetInstance()->GetProxyConnector()) {
        
        if (sp_proxy->GetProxyAddress().empty() == false) {
            bResult = true;
        }
    }
    
    return bResult;
}
    
bool get_http_proxy_address(Address& rProxy)
{
    bool bResult = false;
    
    if (ProxyConnector::Ptr sp_proxy =
            TransportImpl::GetInstance()->GetProxyConnector()) {
        
        const string& proxy_address = sp_proxy->GetProxyAddress();
        
        if (proxy_address.empty() == false) {
            size_t pos = proxy_address.find(':');
            if (pos != string::npos) {
                string ip(proxy_address, 0, pos);
                if (rProxy.SetIP(ip.c_str()) == false) {
                    ip = TranslateToIP(ip);
                    if (!ip.empty()) {
                        rProxy.SetIP(ip.c_str());
                    }
                }
                rProxy.SetPort(atoi(&proxy_address[pos+1]));
                bResult = true;
                
                MLOG("Proxy info: " << rProxy << " (" <<
                     proxy_address << ")");
            }
        }
        
    }
    
    return bResult;
}
    
} // namespace fuze
