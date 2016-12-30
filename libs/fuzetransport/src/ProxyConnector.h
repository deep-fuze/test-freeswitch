//
//  ProxyConnector.h
//  FuzeTransport
//
//  Created by Tim Na on 4/4/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__ProxyConnector__
#define __FuzeTransport__ProxyConnector__

#include <TransportImpl.h>

#include <Thread.h>
#include <Semaphore.h>

#include <queue>

#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
#include <curl/curl.h>
#endif

using std::queue;

namespace fuze {

struct ConnectInfo
{
    typedef fuze_shared_ptr<ConnectInfo> Ptr;
    
    int              tcpID_;         // resource ID of TcpTransceiver
    string           remoteAddress_; // IP:port

#if defined(__ANDROID_API__) || defined(WIN32) || defined(__APPLE__)
    CURL*            pCurl_;         // curl to clean up
#endif

    evutil_socket_t  socket_;        // resulted socket
    
    ConnectInfo();
    virtual ~ConnectInfo();
};
    
//
// using libcurl to establish connection to outside world
//
class ProxyConnector : public Runnable
{
public:
    ProxyConnector();
    virtual ~ProxyConnector();
    
    typedef fuze_shared_ptr<ProxyConnector> Ptr;
    
    void RequestConnection(ConnectInfo::Ptr rInfo);
 
    void SetProxyInfo(const char* pProxyAddress,
                      const char* pCredential,
                      proxy::Type type);
    
    string GetProxyAddress();
    string GetUserCredential();
    proxy::Type GetProxyType();
    
private:
    // implement Runnable interface
    virtual void Run();
    
    ConnectInfo::Ptr GetConnectInfo();
    
    bool                     running_; // to signal thread
    Thread                   connectThread_;
    
    queue<ConnectInfo::Ptr>  workQ_;
    Semaphore                semaphore_;
    MutexLock                qlock_; // for workQ_
    
    MutexLock                strLock_; // credential_, httpProxy_
    string                   credential_;
    string                   proxy_;
    proxy::Type              proxyType_;
};

//
// Interface to proxy_connect
//
bool is_http_proxy_available();

bool get_http_proxy_address(Address& rProxy);
    
} // namespace fuze
    
#endif /* defined(__FuzeTransport__ProxyConnector__) */
