//
//  Thread.h
//  FuzeTransport
//
//  Created by Tim Na on 11/14/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef _FUZE_THREAD_H_
#define _FUZE_THREAD_H_

#include <Compat.h>
#include <string>

#ifdef WIN32

#include <WinSock2.h>
#include <process.h>

typedef DWORD  ThreadID_t;
typedef DWORD  ThreadRet;

#else // end WIN32

#include <pthread.h>
#include <errno.h>

#define WINAPI

typedef pthread_t ThreadID_t;
typedef void*     ThreadRet;

#endif

namespace fuze
{

class Runnable
{
public:
    virtual void Run() = 0; // Interface for thread execution
};

extern "C" { ThreadRet WINAPI dispatch_thread(void* pArg); }
    
//-----------------------------------------------------------------------------
//	Thread
//-----------------------------------------------------------------------------
class Thread
{
public:
    Thread(Runnable* pRunnable, const char* pName = "");
    
    // start the thread
    bool Start(bool bTimeCritical = false);
    
    // check if thread is actively running
    bool IsRunning();
    
    // join the thread
    void Join();
    
    // detach the thread - TODO for Windows
    bool Detach();
    
    // Thread ID of this object
    ThreadID_t  GetThreadID();
    const char* Name();
    
    static ThreadID_t ID();
    
    static void SleepInMs(uint32_t ms);
    
private:

    Runnable*    pRunnable_;
    bool         running_;
    ThreadID_t   threadID_;
#ifdef WIN32
    HANDLE       threadHandle_; // for Windows
#endif
    std::string  name_;
    
    friend ThreadRet WINAPI dispatch_thread(void*);
};
    
} // namespace fuze

#endif // _FUZE_THREAD_H_
