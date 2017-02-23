//
//  MutexLock.cpp
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#include <MutexLock.h>

namespace fuze
{

//------------------------------------------------------------------------------------
// Method: Constructor
// Remark:
//------------------------------------------------------------------------------------
MutexLock::MutexLock()
    : isExternal_(false)
{
#if defined(WIN32)
    cs_ = new CRITICAL_SECTION;
    InitializeCriticalSection(cs_);
#else
    mutex_ = new pthread_mutex_t;
    
    // create recursive lock like Windows default
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(mutex_, &attr);
    pthread_mutexattr_destroy(&attr);
#endif
}

//------------------------------------------------------------------------------------
// Method: Constructor
// Remark:
//------------------------------------------------------------------------------------
MutexLock::MutexLock(const MutexLock* pLock) 
    : isExternal_(true)
{
#if defined(WIN32)
    cs_ = pLock->cs_;
    EnterCriticalSection(cs_);
#else
    mutex_ = pLock->mutex_;
    pthread_mutex_lock(mutex_);
#endif
}

//------------------------------------------------------------------------------------
// Method: Destructor
// Remark:
//------------------------------------------------------------------------------------
MutexLock::~MutexLock()
{
    if (isExternal_) {
#if defined(WIN32)
        LeaveCriticalSection(cs_);
#else
        pthread_mutex_unlock(mutex_);
#endif
    }
    else {
#if defined(WIN32)
        DeleteCriticalSection(cs_);
        delete cs_;
#else
        pthread_mutex_destroy(mutex_);
        delete mutex_;
#endif
    }
}

//------------------------------------------------------------------------------------
// Method: Lock
// Remark:
//------------------------------------------------------------------------------------
void MutexLock::Lock()
{
    if (isExternal_ == false) {
#if defined(WIN32)
        EnterCriticalSection(cs_);
#else
        pthread_mutex_lock(mutex_);
#endif
    }
}

//------------------------------------------------------------------------------------
// Method: Unlock
// Remark:
//------------------------------------------------------------------------------------
void MutexLock::Unlock()
{
    if (isExternal_ == false) {
#if defined(WIN32)
        LeaveCriticalSection(cs_);
#else
        pthread_mutex_unlock(mutex_);
#endif
    }
}

bool MutexLock::Trylock()
{
    if (isExternal_ == false) {
#if defined(WIN32)
        return TryEnterCriticalSection(cs_);
#else
        return (pthread_mutex_trylock(mutex_) == 0);
#endif
    }
    
    return false;
}


} // namespace live
