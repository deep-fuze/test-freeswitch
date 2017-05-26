//
//  Thread.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/14/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include "Thread.h"
#include "Log.h"

#ifndef WIN32
#include <unistd.h>
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

#ifdef WIN32
namespace
{
    const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push,8)  
    typedef struct tagTHREADNAME_INFO
    {
        DWORD dwType; // Must be 0x1000.  
        LPCSTR szName; // Pointer to name (in user addr space).  
        DWORD dwThreadID; // Thread ID (-1=caller thread).  
        DWORD dwFlags; // Reserved for future use, must be zero.  
    } THREADNAME_INFO;
#pragma pack(pop)  
    void SetThreadName(const char* threadName) {
        THREADNAME_INFO info;
        info.dwType = 0x1000;
        info.szName = threadName;
        info.dwThreadID = 0xFFFFFFFF;
        info.dwFlags = 0;
#pragma warning(push)  
#pragma warning(disable: 6320 6322)  
        __try {
            RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
#pragma warning(pop)  
    }
}

#endif

namespace fuze {
    
Thread::Thread(Runnable* pRunnable, const char* pName)
    : pRunnable_(pRunnable)
    , running_(false)
    , threadID_(0)
#ifdef WIN32
    , threadHandle_(0)
#endif
{
    if (pName) {
        name_ = pName;
    }
}

bool Thread::Start(bool bTimeCritical)
{
    bool result = false;
    
#ifdef WIN32
    threadHandle_ = CreateThread(0, 0, dispatch_thread, this, 0, &threadID_);
	if (threadHandle_ != 0) {
        result = running_ = true;
        
        if (bTimeCritical) {
            SetThreadPriority(threadHandle_, THREAD_PRIORITY_TIME_CRITICAL);
        }
    }
    else {
        ELOG("failed to create thread " << name_);
    }
#else
    int res = pthread_create(&threadID_, 0, dispatch_thread, this);
    if (res == 0) {
        result = running_ = true;
        
        if (bTimeCritical) {
            const int min_prio = sched_get_priority_min(SCHED_RR);
            const int max_prio = sched_get_priority_max(SCHED_RR);
            
            if ((min_prio == EINVAL) || (max_prio == EINVAL)) {
                ELOG("unable to retreive min or max priority for threads");
                return true;
            }
            if (max_prio - min_prio <= 2) {
                // There is no room for setting priorities with any granularity.
                return true;
            }
            
            sched_param param;
            param.sched_priority = max_prio-1;
            res = pthread_setschedparam(threadID_, SCHED_RR, &param);
            if (res == EINVAL) {
                ELOG("unable to set thread priority");
            }
        }
    }
    else {
        ELOG("failed to create thread " << name_ << " - " <<
             (res == EAGAIN ? "EAGAIN" : "EINVAL"));
    }
#endif
    
    return result;
}

void Thread::Join()
{
    MLOG("Waiting for thread " << name_ << " to join");
         
#ifdef WIN32
    if (threadHandle_ != 0) {
        WaitForSingleObject(threadHandle_, INFINITE);
        CloseHandle(threadHandle_);
    }
#else
    pthread_join(threadID_, 0);
#endif
    MLOG("Thread " << name_ << " joined");
}

bool Thread::IsRunning()
{
    return running_;
}

bool Thread::Detach()
{
    bool bResult = false;
    
    MLOG(name_);
    
#ifndef WIN32
    int res = pthread_detach(threadID_);
    if (res == 0) {
        bResult = true;
    }
    else {
        ELOG((res == EINVAL ? "Not joinable" : "No such thread ID"));
    }
#endif
    return bResult;
}

ThreadID_t Thread::GetThreadID()
{
    return threadID_;
}

const char* Thread::Name()
{
    return name_.c_str();
}
    
ThreadID_t Thread::ID()
{
#ifdef WIN32
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif
}

void Thread::SleepInMs(uint32_t ms)
{
#ifdef WIN32
    Sleep(ms);
#else
    usleep(ms*1000);
#endif
}
    
ThreadRet WINAPI dispatch_thread(void* pArg)
{
    Thread* p_thread = static_cast<Thread*>(pArg);

    static bool seeded = false;
    if (!seeded) {
        seeded = true;
        
        unsigned seed = (unsigned)time(0);
#ifdef WIN32
        seed += (unsigned)_getpid();
#else
        seed += getpid();
#endif
        // initialize seed for rand()
        srand(seed);
    }

#ifdef WIN32
    SetThreadName(p_thread->name_.c_str());
#elif defined(__APPLE__)
    pthread_setname_np(p_thread->name_.c_str());
#else
    pthread_setname_np(pthread_self(), p_thread->name_.substr(0, 15).c_str());
#endif

    MLOG(p_thread->name_ << " starting");
        
    try {
        p_thread->pRunnable_->Run();
    }
    catch (const std::exception& e) {
        ELOG("exception: " << e.what());
    }
    catch (...) {
        ELOG("Unknown exception thrown");
    }

    p_thread->running_ = false;
    
    MLOG(p_thread->name_ << " exiting");
    
    return 0;
}
    
} // namespace fuze
