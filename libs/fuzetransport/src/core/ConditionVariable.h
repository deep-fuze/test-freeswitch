//
//  Cond.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/10/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FUZE_CONDITION_VARIABLE_H__
#define __FUZE_CONDITION_VARIABLE_H__

#ifndef WIN32
#include <pthread.h>
#include <sys/time.h>
#define INFINITE -1
#endif

#include <MutexLock.h>

namespace fuze
{

class ConditionVariable : private NotCopyable
{
public:
    ConditionVariable();
    virtual ~ConditionVariable();

    // return false if timed out
    //        true  if signaled
    bool Wait(MutexLock& lock, int timeout_ms = INFINITE);
    void Signal();
    void Broadcast();

private:
#ifdef WIN32    
    CONDITION_VARIABLE cond_;
#else
    pthread_cond_t cond_;
#endif

};

} //namespace fuze

#endif