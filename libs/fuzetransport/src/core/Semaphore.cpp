//
//  ConditionalVariable.h
//
//  Created by Tim Na on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <Semaphore.h>

namespace fuze
{

bool Semaphore::Wait(int ms)
{
    bool bResult = true;
    
    lock_.Lock();
    count_ -= 1;
    if (count_ >= 0) {
        lock_.Unlock();
        return true; // don't wait as we have been signaled
    }

    // if timed out then increase the count
    if (cond_.Wait(lock_, ms) == false) {
        count_ += 1;
        bResult = false;
    }
    lock_.Unlock();
    
    return bResult;
}

void Semaphore::Post()
{
    bool signal = false;
    lock_.Lock();
    count_ += 1;
    if (count_ <= 0) {
        signal = true;
    }
    lock_.Unlock();
    
    if (signal) {
        cond_.Signal();
    }
}

} // namespace live
