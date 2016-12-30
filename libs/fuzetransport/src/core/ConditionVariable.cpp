//
//  ConditionVariable.cpp
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include "ConditionVariable.h"
#include "Exception.h"
#include "Log.h"

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

ConditionVariable::ConditionVariable()
{
#ifdef WIN32    
    InitializeConditionVariable(&cond_);
#else
    if (int ret = pthread_cond_init(&cond_, NULL)) {
        _ELOG_("Error in pthread_cond_init() err:" <<
               ret << " errno=" << errno);
        throw InitException("pthread_cond_init() error");
    }
#endif    
}

ConditionVariable::~ConditionVariable()
{
#ifndef WIN32
    pthread_cond_destroy(&cond_);
#endif
}

bool ConditionVariable::Wait(MutexLock& lock, int timeout_ms)
{
    DLOG(timeout_ms << " ms");
    
    bool signaled = true;

#ifdef WIN32
    if (timeout_ms < 0) { // wait until event
        SleepConditionVariableCS(&cond_, lock.cs_, INFINITE);
    }
    else {
        if (SleepConditionVariableCS(&cond_, lock.cs_, timeout_ms) == 0) {
            if (GetLastError() == ERROR_TIMEOUT) {
                signaled = false;
            }
        }
    }
#else
    if (timeout_ms < 0) { // wait until event
        if (int ret = pthread_cond_wait(&cond_, lock.mutex_)) {
            ELOG("pthread_cond_wait failed - ret: " << ret);
        }
    }
    else { // timed wait
        timeval  tv;
        timespec ts;

        gettimeofday(&tv, 0);

        ts.tv_sec  = tv.tv_sec;
        ts.tv_nsec = tv.tv_usec * 1000;
        
        DLOG("before sec: " << ts.tv_sec << " nsec: " << ts.tv_nsec);
        
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        
        const long ONE_SECOND = 1000000000;
        if (ts.tv_nsec > ONE_SECOND) {
            DLOG("overflowed sec: " << ts.tv_sec << " nsec: " << ts.tv_nsec);
            ts.tv_sec += ts.tv_nsec / ONE_SECOND;
            ts.tv_nsec %= ONE_SECOND;
            DLOG("final wait sec: " << ts.tv_sec - tv.tv_sec <<
                 " nsec: " << ts.tv_nsec);
        }
        else {
            DLOG("sec: " << ts.tv_sec << " nsec: " << ts.tv_nsec <<
                 " final wait sec: " << ts.tv_sec - tv.tv_sec <<
                 " nsec: " << ts.tv_nsec - tv.tv_usec * 1000);
        }
        
        int ret = pthread_cond_timedwait(&cond_, lock.mutex_, &ts);
        
        if (ret != 0) {
            if (ret == ETIMEDOUT) {
                signaled = false;
            }
            else if (ret == EINVAL) {
                ELOG("pthread_cond_timedwait failed (" << timeout_ms << " ms");
            }
        }
    }
#endif

    return signaled;
}

void ConditionVariable::Signal()
{
#ifdef WIN32    
    WakeConditionVariable(&cond_);
#else
    pthread_cond_signal(&cond_);
#endif
}

void ConditionVariable::Broadcast()
{
#ifdef WIN32
    WakeAllConditionVariable(&cond_);
#else
    pthread_cond_broadcast(&cond_);
#endif
}

} // namespace