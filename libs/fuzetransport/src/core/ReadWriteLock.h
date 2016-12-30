//
//  ReadWriteLock.hpp
//  FuzeTransport
//
//  Created by Tim Na on 12/20/16.
//  Copyright © 2016 Fuze. All rights reserved.
//

#ifndef ReadWriteLock_h_
#define ReadWriteLock_h_

#ifdef WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif

#include <NotCopyable.h>

namespace fuze {
    
class ReadWriteLock : private NotCopyable
{
public:
    ReadWriteLock();
    ~ReadWriteLock();
    
    void ReadLock();
    void ReadUnlock();
    
    void WriteLock();
    void WriteUnlock();

    bool TryReadLock();
    bool TryWriteLock();
    
    void Unlock();
    
private:

#ifdef WIN32
    SRWLOCK           rwLock_;
#else
    pthread_rwlock_t  rwLock_;
#endif
};

class ReadLock : private NotCopyable
{
public:
    ReadLock(ReadWriteLock* p);
    ~ReadLock();
    
private:
    ReadWriteLock* pLock_;
};

class WriteLock : private NotCopyable
{
public:
    WriteLock(ReadWriteLock* p);
    ~WriteLock();
    
private:
    ReadWriteLock* pLock_;
};
    
} // namespace fuze

#endif /* ReadWriteLock_hpp */
