//
//  Server.h
//  FuzeTransport
//
//  Created by Tim Na on 1/10/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__Server__
#define __FuzeTransport__Server__

#include <ServerCore.h>
#include <MutexLock.h>
#include <map>
#include <queue>

#include <Mapping.h>
#include <MediaBridge.h>

namespace fuze {
        
using std::map;
using std::multimap;
using std::queue;
using std::pair;

//
// This class serves the purpose of receiving connection in port 443.
//
// There will be following kinds of connection requests.
//
//  1) TCP
//  2) TLS
//  3) HTTP Connect
//  4) HTTP Connect + TLS (TBD after HTTP authentication)
//
// Once connection is established by above means. This class will expect
// Fuze Transport Protocol message to communicate mapping of incoming
// connections to application's connections. Once corresponding
// application connection is identified, it will replace the
// Transceiver so that it would be transparent to application what
// goes underneath.
//
class Server
{
public:
    Server();
    virtual ~Server();

    typedef fuze_shared_ptr<Server> Ptr;
    
    static const uint16_t PORT = 443; // our listening port for
                                      // firewall traversal
    
    // lazy-initialization due to Singleton app
    bool Initialize();
    
    // Tcp Listener interface
    void OnListenEvent(evutil_socket_t sock, short what);
    
    // Create connection binding for the socket that this
    // Fuze Transport is listenting to. This is called
    // when UDP bind or TCP listen is happneing
    void SetConnectionBinding(int connID);
    
    // Remove the binding
    void RemoveConnectionBinding(int connID);
    
    // Remove core from coreSet_
    void RemoveServerCore(int coreID);
    
    // Retrieving binding info of local listeners
    bool GetBindingInfo(BindingInfo& rInfo, Mapping& mapReq);
    
private:
    
    evutil_socket_t   socket_;
    event*            pReadEvent_;
    
    MediaBridge::Ptr  spBridge_;
    
private: // connection mapping
    
    typedef uint16_t BindingKey; // Transport (16 bits) + Port (16 bits)
    typedef map<BindingKey, BindingInfo>  BindingMap;
    
    BindingMap  bindingMap_;
    MutexLock   lock_;    // protect bindingMap_
    set<int>    coreSet_; // currently active ServerCore
                          // no need for lock as its usage
                          // is exclusive to libevent thread
private: // logic to guard against faulty 443 connection
    static const int64_t MAX_CORE_IDLE_MS = 5000;
    static const int64_t CLEANUP_PERIOD   = 5000;
    void CleanupCoreSet(); // method that checks for connections
                           // that are gone without closing from far end
    int64_t lastCleanTime_;

};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__Server__) */
