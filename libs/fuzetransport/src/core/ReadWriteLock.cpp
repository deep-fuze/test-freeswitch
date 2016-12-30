//
//  ReadWriteLock.cpp
//  FuzeTransport
//
//  Created by Tim Na on 12/20/16.
//  Copyright © 2016 Fuze. All rights reserved.
//

#include "ReadWriteLock.h"
#include <Log.h>

namespace fuze {
    
ReadWriteLock::ReadWriteLock()
{
#ifdef WIN32
    rwLock_ = SRWLOCK_INIT;
#else
    int err = pthread_rwlock_init(&rwLock_, 0);
    if (err != 0) {
        _ELOG_("pthread_rwlock_init error: " << err);
    }
#endif
}

ReadWriteLock::~ReadWriteLock()
{
#ifndef WIN32
    int err = pthread_rwlock_destroy(&rwLock_);
    if (err != 0) {
        _ELOG_("pthread_rwlock_destroy error: " << err)
    }
#endif
}

void ReadWriteLock::ReadLock()
{
#ifdef WIN32
    ::AcquireSRWLockShared(&rwLock_);
#else
    int err = pthread_rwlock_rdlock(&rwLock_);
    if (err != 0) {
        _ELOG_("pthread_rwlock_rdlock error: " << err)
    }
#endif
}

void ReadWriteLock::ReadUnlock()
{
#ifdef WIN32
    ::ReleaseSRWLockShared(&rwLock_);
#else
    int err = pthread_rwlock_unlock(&rwLock_);
    if (err != 0) {
        _ELOG_("pthread_rwlock_rdlock error: " << err)
    }
#endif
}

void ReadWriteLock::WriteLock()
{
#ifdef WIN32
    ::AcquireSRWLockExclusive(&rwLock_);
#else
    int err = pthread_rwlock_wrlock(&rwLock_);
    if (err != 0) {
        _ELOG_("pthread_rwlock_wrlock error: " << err)
    }
#endif
}
    
void ReadWriteLock::WriteUnlock()
{
#ifdef WIN32
    ::ReleaseSRWLockExclusive(&rwLock_);
#else
    int err = pthread_rwlock_unlock(&rwLock_);
    if (err != 0) {
        _ELOG_("pthread_rwlock_rdlock error: " << err)
    }
#endif
}
    
bool ReadWriteLock::TryReadLock()
{
    bool result = false;
#ifdef WIN32
    result = (::TryAcquireSRWLockShared(&rwLock_) != FALSE);
#else
    result = pthread_rwlock_tryrdlock(&rwLock_);
#endif
    return result;
}

bool ReadWriteLock::TryWriteLock()
{
    bool result = false;
#ifdef WIN32
    result = (::TryAcquireSRWLockExclusive(&rwLock_) != FALSE);
#else
    result = pthread_rwlock_trywrlock(&rwLock_);
#endif
    return result;
}

ReadLock::ReadLock(ReadWriteLock* p)
    : pLock_(p)
{
    if (pLock_) pLock_->ReadLock();
}

ReadLock::~ReadLock()
{
    if (pLock_) pLock_->ReadUnlock();
}

WriteLock::WriteLock(ReadWriteLock* p)
    : pLock_(p)
{
    if (pLock_) pLock_->WriteLock();
}

WriteLock::~WriteLock()
{
    if (pLock_) pLock_->WriteUnlock();
}
    
} // namespace fuze
