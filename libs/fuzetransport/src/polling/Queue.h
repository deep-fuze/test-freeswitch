//
//  Queue.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/10/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FUZE_QUEUE_H__
#define __FUZE_QUEUE_H__

#include <queue>

#include <event2/event.h>

#include "MutexLock.h"
#include "ConditionVariable.h"

using std::queue;
using namespace std;

namespace fuze
{
    
template <class T>
class FuzeQ
{
private:
    queue< fuze_shared_ptr<T> > q_;
    
    MutexLock              lock_;
    ConditionVariable      cond_;
    size_t                 size_; // MQT-3004
    
public:
    FuzeQ();
    virtual ~FuzeQ();

    fuze_shared_ptr<T> GetNext(bool blocking=true);
    void InsertNode(fuze_shared_ptr<T> pNode);
    bool WaitUntil(int timeout);
    inline uint32_t Size() { return (uint32_t)size_; }
    void Clear();
};
  
template <class T>
FuzeQ<T>::FuzeQ()
    : size_(0)
{
}

template <class T>
FuzeQ<T>::~FuzeQ()
{
}
 
template <class T>
fuze_shared_ptr<T> FuzeQ<T>::GetNext(bool blocking)
{
    fuze_shared_ptr<T> next;
   
    if (blocking) {
        lock_.Lock();
    } else {
        if (!lock_.Trylock()) {
	    return next;
        }
    }
 
    while (!size_) {
        if (blocking == true) {
            cond_.Wait(lock_, -1);
        } else {
            break;
        }
        
        if (size_) {
            break;
        }
    }

    if (size_) {
        next = q_.front();
        q_.pop();
        size_--;
    }
    
    lock_.Unlock();
    
    return next;
}
   
template <class T>
void FuzeQ<T>::InsertNode(fuze_shared_ptr<T> pNode)
{
    lock_.Lock();

    q_.push(pNode);
    size_++;
    
    cond_.Signal();
    lock_.Unlock();
}
  
template<class T>
bool FuzeQ<T>::WaitUntil(int timeout)
{
    if (timeout) {
        lock_.Lock();
        
        if (!size_) {
            cond_.Wait(lock_, (timeout < 0 ? -1 : timeout));
        }
        
        lock_.Unlock();
    }
    
    return (size_ > 0);
}

template<class T>
void FuzeQ<T>::Clear()
{
    queue< fuze_shared_ptr<T> > empty_q;
    
    lock_.Lock();
    swap(q_, empty_q);
    size_ = 0;
    lock_.Unlock();
}
    
} //namespace fuze

#endif
