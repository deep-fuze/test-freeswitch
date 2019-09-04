//
//  TimerService.h
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#ifndef TimerService_h
#define TimerService_h

#include <Transport.h>
#include <Thread.h>
#include <Semaphore.h>
#include <map>

namespace fuze {

using std::multimap;
    
//
// Simple timer service using single thread
//
class TimerService : public Runnable
{
public:
    TimerService();
    virtual ~TimerService();
    
    void Terminate();
    
    // Weak Pointer interface
    int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, int32_t appData,
                         const char* pFile, int line);
    void    StopTimer(Timer::Ptr pTimer, int64_t handle);
    
    // Raw Pointer interface - only if you know what you are doing
    int64_t StartTimerEx(Timer* pTimer, int32_t ms, int32_t appData,
                         const char* pFile, int line);
    void    StopTimer(Timer* pTimer, int64_t handle);
    
private:
    
    // Runnable interface
    virtual void Run();
    
    struct TimerInfo
    {
        Timer::WPtr wpTimer_;
        Timer*      pTimer_; // for matching id while stop timer
        int32_t     appData_;
        bool        useRaw_;
        const char* pFile_;
        int         line_;
    };
    
    void AddTimer(TimerInfo& rInfo, int64_t handle);
    void RemoveTimer(Timer* pTimer, int64_t handle);
    
    typedef multimap<int64_t, TimerInfo> TimerPool;
    
    bool       running_;
    Semaphore  finish_; // to synchronize finish sequence
    
    Thread     thread_;
    Semaphore  sem_;
    
    TimerPool  pool_;
    MutexLock  lock_;
};

} // namespace fuze

#endif /* TimerService_h */
