//
//  MutexLock.h
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
//  NOTE:
//   
//  Two ways to use the mutex lock here
//
//   1. for small and exception free section of code
//
//      MutexLock my_lock;
//      my_lock.Lock()
//      ....
//      my_lock.Unlock() 
//      
//   2. For method scoped lock for exception safe code
//      
//      MutexLock scoped(&my_lock);
//

#ifndef MUTEXLOCK_H_
#define MUTEXLOCK_H_

#include <Compat.h>
#include <NotCopyable.h>

#ifdef WIN32
#include <WinSock2.h> // for CRITICAL_SECTION
#else
#include <pthread.h>
#endif

namespace fuze
{

class MutexLock : private NotCopyable
{
public:
    // Constructor for internal lock
    explicit MutexLock();
    // Constructor for external lock
    explicit MutexLock(const MutexLock* pLock);
    virtual ~MutexLock();

    void Lock();
    void Unlock();
    void TryLock();
    
private:
#if defined(WIN32)
    CRITICAL_SECTION*   cs_;
#else
    pthread_mutex_t*    mutex_;
#endif
    bool                isExternal_;

    friend class ConditionVariable;
};

} // namespace fuze

#endif
