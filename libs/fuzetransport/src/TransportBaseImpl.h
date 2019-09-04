//
//  TransportBaseImpl.h
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TransportBaseImpl__
#define __FuzeTransport__TransportBaseImpl__

#include <TransportImpl.h>
#include <Resource.h>

namespace fuze {
    
class TransportBaseImpl : public TransportBase
                        , public Resource
{
public:
    explicit TransportBaseImpl(int baseID);

    // TransportBase Interface
    virtual void Initialize(int numOfThreads = 1);
    virtual void RegisterObserver(BaseObserver* pObserver);
    virtual void RegisterObserver(BaseObserver::WPtr wPtr);
    virtual void DeregisterObserver();
    virtual void SetType(TransportBase::Type eType);
    virtual Connection::Ptr CreateConnection(const char* pName = 0);
    virtual void NotifyCongestion(CongestionInfo& rInfo);
    
    // Resource Interface
    virtual void Reset();
    
    // Debug purpose
    void SetName(const char* pName);
        
    // Remove connection id from active set
    void RemoveConnection(int connID);

    // Add a new TCP connection into base for now
    void AddNewConnection(evutil_socket_t newSock, bool overTLS = false);

    TransportBase::Type GetBaseType();
    
    void OnCongestion(const CongestionInfo& rInfo);
    
    // Name used on base type string
    static const char* SRC_BASE_TYPE;
    
private:
    
    TransportBase::Type  type_;
    BaseObserver*        pObserver_;
    BaseObserver::WPtr   wpObserver_;
    MutexLock            observerLock_;
    set<int>             conSet_;   // connection set
    MutexLock            lock_;     // for conSet_
    char                 name_[10]; // take first 8 char from app (debug purpose)
};
        
//
// The purpose of NoBaseObserver to do away with lock and
// we always have a valid pointer for callback
//
class NoBaseObserver : public BaseObserver
{
public:
    static BaseObserver* GetInstance() { return &sInstance_; }
    virtual void OnNewConnection(Connection::Ptr spNewConnection) {}
    virtual void OnCongestion(const CongestionInfo& rInfo) {}
private:
    NoBaseObserver() {}
    static NoBaseObserver sInstance_;
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__TransportBaseImpl__) */
