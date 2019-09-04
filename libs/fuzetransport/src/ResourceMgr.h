//
//  ResourceMgr.h
//  FuzeTransport
//
//  Created by Tim Na on 11/15/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__ResourceMgr__
#define __FuzeTransport__ResourceMgr__

#include <Transport.h>
#include <Resource.h>
#include <MutexLock.h>
#include <vector>
#include <queue>

namespace fuze {

using std::vector;
using std::queue;
    
class TransportBaseImpl;
class ConnectionImpl;
class Transceiver;
class ServerCore;
    
//
//  ResourceMgr
//
//  Instead of new/delete objects, this class will
//  hold the object in array so that its access is
//  fast and safe.
//
class ResourceMgr : public TransportUser
{
public:
    static ResourceMgr* GetInstance();
    virtual ~ResourceMgr();

    TransportBaseImpl*  GetNewBase();
    ConnectionImpl*     GetNewConnection();
    Transceiver*        GetNewTransceiver(ConnectionType eType);
    ServerCore*         GetNewServerCore();
    
    // Get base/connection object only when active
    // return value 0 when the object is not active
    TransportBaseImpl*  GetBase(int baseID);
    ConnectionImpl*     GetConnection(int connID);
    Transceiver*        GetTransceiver(Resource::Type type, int tranID);
    ServerCore*         GetServerCore(int coreID);
    
    // the objects here are expected to be reset
    // before Release is called
    void Release(Resource* p);
    
private:
    ResourceMgr();
    
    Resource* GetNewResource(Resource::Type type);
    Resource* GetResource(Resource::Type type, int ID);
    
    static ResourceMgr* spInstance_;
    static MutexLock    sLock_;
    
    vector<Resource*>   resources_[Resource::MAX_NUM];
    queue<Resource*>    idle_[Resource::MAX_NUM];
    MutexLock           lock_[Resource::MAX_NUM];
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__ResourceMgr__) */
