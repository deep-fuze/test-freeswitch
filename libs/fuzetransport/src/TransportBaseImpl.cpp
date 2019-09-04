//
//  TransportBaseImpl.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <ConnectionImpl.h>
#include <ResourceMgr.h>
#include <Log.h>

#ifdef __linux__
#include <cstring> // memset
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Base[b" << ID() << name_ << "] " << __FUZE_FUNC__ << ": " << B)

namespace fuze {

NoBaseObserver NoBaseObserver::sInstance_;
    
const char* TransportBaseImpl::SRC_BASE_TYPE = "SrcBaseType";
    
TransportBaseImpl::TransportBaseImpl(int baseID)
    : Resource(baseID)
    , type_(TransportBase::NONE)
    , pObserver_(NoBaseObserver::GetInstance())
{
    SetName(0);
    DLOG("Created");
}

void TransportBaseImpl::Initialize(int numOfThreads)
{
}

void TransportBaseImpl::SetName(const char* pName)
{
    memset(name_, 0, 10); // init name
    if (pName && *pName) {
        name_[0] = ':';
        for (int i = 1; i < 9; ++i) {
            if (pName[i-1]) {
                name_[i] = pName[i-1];
            }
            else {
                break;
            }
        }
    }
}
    
void TransportBaseImpl::Reset()
{
    pObserver_ = NoBaseObserver::GetInstance();
    
    if (IsActive()) {
        DLOG("ACTIVE -> ZOMBIE");
        SetZombie();
        
        if (type_ != TransportBase::NONE) {
            TransportImpl::GetInstance()->SetCongestionBaseID(type_, INVALID_ID);
            type_ = TransportBase::NONE;
        }
        
        MutexLock scoped(&lock_);
        // if there are still connections not removed, remove them
        while (conSet_.empty() == false) {
            set<int>::iterator iter = conSet_.begin();
            int conn_id = *iter;
            conSet_.erase(iter);
            
            // if base is reset before connection, we may still have
            // active connections which need to be reset as well
            if (ConnectionImpl* p_con =
                    ResourceMgr::GetInstance()->GetConnection(conn_id)) {
                p_con->SetBaseID(INVALID_ID);
                TransportImpl::GetInstance()->RequestReset(Resource::CONNECTION, conn_id);
            }
        }
    }
}
    
void TransportBaseImpl::RegisterObserver(BaseObserver* pObserver)
{
    MutexLock scoped(&observerLock_);
    pObserver_ = pObserver;
}

void TransportBaseImpl::RegisterObserver(BaseObserver::WPtr wPtr)
{
    wpObserver_ = wPtr;
}
    
void TransportBaseImpl::DeregisterObserver()
{
    pObserver_ = NoBaseObserver::GetInstance();
}

void TransportBaseImpl::SetType(TransportBase::Type eType)
{
    MLOG("base type changed: " << toStr(type_) << " -> " << toStr(eType));
    type_ = eType;
    
    TransportImpl::GetInstance()->SetCongestionBaseID(eType, ID());
}

TransportBase::Type TransportBaseImpl::GetBaseType()
{
    return type_;
}
    
Connection::Ptr TransportBaseImpl::CreateConnection(const char* pName)
{
    Connection::Ptr sp_con;
    
    if (ConnectionImpl* p = ResourceMgr::GetInstance()->GetNewConnection()) {
        sp_con.reset(p, ConnectionEnded);
        p->SetBaseID(ID());
        
        if (pName) {
            p->SetName(pName);
        }
        
        MutexLock scoped(&lock_);
        conSet_.insert(p->ID());
    }
    
    return sp_con;
}

void TransportBaseImpl::NotifyCongestion(CongestionInfo& rInfo)
{
    MLOG("SrcBaseType - " << toStr(type_))
    
    rInfo[SRC_BASE_TYPE] = toStr(type_);
    
    TransportImpl::GetInstance()->RequestCongestion(rInfo);
}
    
void TransportBaseImpl::RemoveConnection(int connID)
{
    if (connID != INVALID_ID) {
        MutexLock scoped(&lock_);
        set<int>::iterator iter = conSet_.find(connID);
        if (iter != conSet_.end()) {
            DLOG("Removing Connection " << connID);
            conSet_.erase(iter);
        }
    }
}

void TransportBaseImpl::AddNewConnection(int newSock, bool overTLS)
{
    if (Connection::Ptr sp_con = CreateConnection()) {
        // set the content of connection
        if (ConnectionImpl* p = dynamic_cast<ConnectionImpl*>(sp_con.get())) {
            p->SetBaseID(ID());
            if (p->Initialize(CT_TCP, newSock, overTLS)) {
                uint64_t start_time = GetTimeMs();
                
                try {
                    if (wpObserver_.expired()) {
                        MutexLock scoped(&observerLock_);
                        if (pObserver_) {
                            pObserver_->OnNewConnection(sp_con);
                        }
                    }
                    else {
                        if (BaseObserver::Ptr sp = wpObserver_.lock()) {
                            sp->OnNewConnection(sp_con);
                        }
                    }
                }
                catch (std::exception& ex) {
                    ELOG("exception - " << ex.what());
                }
                catch (...) {
                    ELOG("unknown exception");
                }
                
                int64_t diff = GetTimeMs() - start_time;
                if (diff > 5) {
                    WLOG("App delayed libevent thread " << diff << " ms");
                }
            }
            else {
                ELOG("Failed to initialize");
            }
        }
    }
}

void TransportBaseImpl::OnCongestion(const CongestionInfo &rInfo)
{
    uint64_t start_time = GetTimeMs();
    
    try {
        if (wpObserver_.expired()) {
            MutexLock scoped(&observerLock_);
            if (pObserver_) {
                pObserver_->OnCongestion(rInfo);
            }
        }
        else {
            if (BaseObserver::Ptr sp = wpObserver_.lock()) {
                sp->OnCongestion(rInfo);
            }
        }
    }
    catch (std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
    
    int64_t diff = GetTimeMs() - start_time;
    if (diff > 5) {
        WLOG("App delayed libevent thread " << diff << " ms");
    }
}
    
} // namespace fuze
