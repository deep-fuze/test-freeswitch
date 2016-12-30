//
//  Semaphore.h
//  FuzeTransport
//
//  Created by Tim Na on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef _SEMAPHORE_H__
#define _SEMAPHORE_H__

#include <ConditionVariable.h>
#include <NotCopyable.h>
#include <MutexLock.h>

#ifndef INFINITE
const int INFINITE = 0xffffffff;
#endif

namespace fuze
{

class Semaphore : private NotCopyable
{
public:
    explicit Semaphore() : count_(0) {}
    virtual ~Semaphore() { cond_.Broadcast(); }

    // return false if timed out, true if signaled
    bool Wait(int ms = INFINITE); // milli-seconds
    void Post();
    int  GetCount() const {return count_;} // semaphore count - watch this is only informal
    
private:

    int                count_;   // semaphore count
    ConditionVariable  cond_;
    MutexLock          lock_;
};

} // namespace fuze

#endif // CONDITION_VARIABLE_H_
