//
//  ResourceMgr.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/15/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <ResourceMgr.h>

#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <TcpTransceiver.h>
#include <TcpListener.h>
#include <UdpTransceiver.h>
#include <DtlsTransceiver.h>
#include <ServerCore.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

void fuze_transport_at_exit();
    
ResourceMgr* ResourceMgr::spInstance_;
MutexLock    ResourceMgr::sLock_;
    
ResourceMgr* ResourceMgr::GetInstance()
{
    if (!spInstance_) {
        MutexLock scoped(&sLock_);
        if (!spInstance_) {
            ResourceMgr* p = new ResourceMgr;
            Transport::GetInstance()->
                RegisterTransportUser(p, TransportUser::TRANSPORT_RSR_MGR);
            spInstance_ = p;
        }
    }
    
    return spInstance_;
}

ResourceMgr::ResourceMgr()
{
}
    
ResourceMgr::~ResourceMgr()
{
#if 0
    // as Buffer has static global variable, we can't
    // control the order of destruction of these.
    // As resource deallocation is not crucial thing to do
    // we just leak them here until RawBuffer provides
    // a way to query its existance.
    for (uint32_t type = Resource::BASE; type < Resource::MAX_NUM; ++type) {
        MutexLock scoped(&lock_[type]);
        for (size_t i = 0, iSize = resources_[type].size(); i < iSize; ++i) {
            delete resources_[type][i];
        }
        resources_[type].clear();
    }
#endif
}

Resource* ResourceMgr::GetNewResource(Resource::Type type)
{
    Resource* p = 0;
    
    using std::nothrow;
    
    MutexLock scoped(&lock_[type]);
    
    if (idle_[type].empty()) {
        int new_id = static_cast<int>(resources_[type].size());
        switch (type)
        {
        case Resource::BASE:
            p = new (nothrow) TransportBaseImpl(new_id);
            break;
        case Resource::CONNECTION:
            p = new (nothrow) ConnectionImpl(new_id);
            break;
        case Resource::TCP_LISTENER:
            p = new (nothrow) TcpListener(new_id);
            break;
        case Resource::TCP_TRANSCEIVER:
            p = new (nothrow) TcpTransceiver(new_id);
            break;
        case Resource::UDP_TRANSCEIVER:
            p = new (nothrow) UdpTransceiver(new_id);
            break;
        case Resource::DTLS_TRANSCEIVER:
            p = new (nothrow) DtlsTransceiver(new_id);
            break;
        case Resource::SERVERCORE:
            p = new (nothrow) ServerCore(new_id);
            break;
        case Resource::MAX_NUM:
        default:
            ELOG("Wrong input type");
        }
        
        if (p) {
            resources_[type].push_back(p);
            p->type_ = type;
        }
    }
    else {
        p = idle_[type].front();
        idle_[type].pop();
    }
    
    if (p) {
        p->status_ = Resource::ACTIVE;
    }
    
    return p;
}
    
TransportBaseImpl* ResourceMgr::GetNewBase()
{
    return dynamic_cast<TransportBaseImpl*>(GetNewResource(Resource::BASE));
}
    
ConnectionImpl* ResourceMgr::GetNewConnection()
{
    return dynamic_cast<ConnectionImpl*>(GetNewResource(Resource::CONNECTION));
}

Transceiver* ResourceMgr::GetNewTransceiver(ConnectionType eType)
{
    Transceiver* p = 0;
    
    switch (eType)
    {
    case CT_UDP:
        p = dynamic_cast<Transceiver*>(GetNewResource(Resource::UDP_TRANSCEIVER));
        break;
    case CT_TLS:
    case CT_TCP:
        p = dynamic_cast<Transceiver*>(GetNewResource(Resource::TCP_TRANSCEIVER));
        break;
    case CT_TCP_LISTENER:
        p = dynamic_cast<Transceiver*>(GetNewResource(Resource::TCP_LISTENER));
        break;
    case CT_DTLS_CLIENT:
    case CT_DTLS_SERVER:
    {
        DtlsTransceiver* p_dtls
            = dynamic_cast<DtlsTransceiver*>(GetNewResource(Resource::DTLS_TRANSCEIVER));
        p_dtls->SetConnectionType(eType);
        p = p_dtls;
        break;
    }
    default:
        ELOG("Unexpected transceiver type " << toStr(eType))
    }
    
    return p;
}    
    
ServerCore* ResourceMgr::GetNewServerCore()
{
    return dynamic_cast<ServerCore*>(GetNewResource(Resource::SERVERCORE));
}
    
Resource* ResourceMgr::GetResource(Resource::Type type, int ID)
{
    Resource* p = 0;
    
    MutexLock scoped(&lock_[type]);
    
    if ((0 <= ID) && (ID < (int)resources_[type].size())) {
        if (resources_[type][ID]->status_ == Resource::ACTIVE) {
            p = resources_[type][ID];
        }
    }
    
    return p;
}
    
TransportBaseImpl* ResourceMgr::GetBase(int baseID)
{
    return dynamic_cast<TransportBaseImpl*>(GetResource(Resource::BASE, baseID));
}
    
ConnectionImpl* ResourceMgr::GetConnection(int connID)
{
    return dynamic_cast<ConnectionImpl*>(GetResource(Resource::CONNECTION, connID));
}

Transceiver* ResourceMgr::GetTransceiver(Resource::Type type, int tranID)
{
    return dynamic_cast<Transceiver*>(GetResource(type, tranID));
}
    
ServerCore* ResourceMgr::GetServerCore(int coreID)
{
    return dynamic_cast<ServerCore*>(GetResource(Resource::SERVERCORE, coreID));
}

void ResourceMgr::Release(Resource* p)
{
    if (p->IsActive()) {
        WLOG("Active state detected");
        p->Reset();
    }
    else if (p->status_ == Resource::IDLE) {
        WLOG("Already idle state on " << p->GetTypeString() << " [" << p->ID() << "]");
        return;
    }

    p->status_ = Resource::IDLE;
    DLOG(p->GetTypeString() << ": " << p->ID());
    
    MutexLock scoped(&lock_[p->type_]);
    idle_[p->type_].push(p);
}

const char* Resource::GetStatusString() const
{
    switch (status_)
    {
    case IDLE:   return "IDLE";
    case ACTIVE: return "ACTIVE";
    case ZOMBIE: return "ZOMBIE";
    default:     return "INVALID";
    }
}

const char* Resource::GetTypeString() const
{
    switch(type_)
    {
    case BASE:             return "Base";
    case CONNECTION:       return "Connection";
    case TCP_LISTENER:     return "TcpListener";
    case TCP_TRANSCEIVER:  return "TcpTransceiver";
    case UDP_TRANSCEIVER:  return "UdpTransceiver";
    case DTLS_TRANSCEIVER: return "DtlsTransceiver";
    case SERVERCORE:       return "ServerCore";
    default:               return "Invalid";
    }
}
    
} // namespace fuze
