//
//  Timer.h
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef Timer_h
#define Timer_h

#include "Common.h"

namespace fuze {

//
// Timer interface
//
class Timer
{
public:
    typedef fuze_shared_ptr<Timer> Ptr;
    typedef fuze_weak_ptr<Timer>   WPtr;
    
    virtual void OnTimer(int32_t AppData) {}
    virtual void OnTimerEx(void* AppData) {}
    
    inline virtual ~Timer() {}
};

//
// API for using global TimerService in Transport singleton
//

// macro hack to indicate where timer is started
#define StartTimer(A, B, C) StartTimerEx(A, B, C, __FILE__, __LINE__)

int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line);
int64_t StartTimerEx(Timer::Ptr pTimer, int32_t ms, void* appData,
                     const char* pFile, int line);
int64_t StartTimerEx(Timer* pTimer, int32_t ms, int32_t appData,
                     const char* pFile, int line);

//
// NOTE: watch so that StopTimer using shared_ptr is not called within destructor
//
void StopTimer(Timer::Ptr pTimer, int64_t handle);
void StopTimer(Timer* pTimer, int64_t handle);

//
// TimerService ABC for creating own timer service in application
//
class TimerService
{
public:
    typedef fuze_shared_ptr<TimerService> Ptr;
    
    static Ptr Create(const char* pName = "");
    
    virtual void Terminate() = 0;
    
    // Weak Pointer interface
    virtual int64_t StartTimerEx(Timer::Ptr pTimer,
                                 int32_t ms, int32_t appData,
                                 const char* pFile, int line) = 0;
    
    // Weak Pointer with void pointer as returned parameter
    virtual int64_t StartTimerEx(Timer::Ptr pTimer,
                                 int32_t ms, void* appData,
                                 const char* pFile, int line) = 0;
    
    // Raw Pointer interface - only if you know what you are doing
    virtual int64_t StartTimerEx(Timer* pTimer,
                                 int32_t ms, int32_t appData,
                                 const char* pFile, int line) = 0;
    
    // StopTimer using raw pointer or shared_ptr
    //
    //  note: when shared_ptr one is used don't call it in destructor of Timer
    //
    virtual void StopTimer(Timer* pTimer, int64_t handle) = 0;
    virtual void StopTimer(Timer::Ptr pTimer, int64_t handle) = 0;
    
    virtual ~TimerService() {}
};

} // namespace fuze
    
#endif /* Timer_h */
