//
//  TimerService.cpp
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#include "TimerService.h"
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": [" << name_ << "] " << B)

namespace fuze {

TimerService::Ptr TimerService::Create(const char* pName)
{
    return TimerService::Ptr(new TimerServiceImpl(pName));
}
    
TimerServiceImpl::TimerServiceImpl(const char* pName)
    : thread_(this, pName)
    , name_(pName)
{
    running_ = true;
    thread_.Start(true);
}

TimerServiceImpl::~TimerServiceImpl()
{
    Terminate();
}

void TimerServiceImpl::Terminate()
{
    if (running_) {
        running_ = false;
        sem_.Post();
        // wait maximum 2 seconds
        if (finish_.Wait(2000) == false) {
            ELOG("waiting on timer thread timed out..");
        }
    }
}

int64_t TimerServiceImpl::StartTimerEx(Timer::Ptr spTimer, int32_t ms, int32_t appData,
                                       const char* pFile, int line)
{
    pFile = (strrchr(pFile, _DIR_MARK_) ? strrchr(pFile, _DIR_MARK_) + 1 : pFile);
    
    int64_t handle = GetTimeMs() + ms;
    
    DLOG("handle: " << handle);
    
    TimerInfo info;
    info.wpTimer_ = spTimer;
    info.pTimer_  = spTimer.get();
    info.appData_ = appData;
    info.appDataEx_ = NULL;
    info.useRaw_  = false;
    info.pFile_   = pFile;
    info.line_    = line;
    
    AddTimer(info, handle);
    
    return handle;
}

int64_t TimerServiceImpl::StartTimerEx(Timer::Ptr spTimer, int32_t ms, void* appData,
                                       const char* pFile, int line)
{
    pFile = (strrchr(pFile, _DIR_MARK_) ? strrchr(pFile, _DIR_MARK_) + 1 : pFile);

    int64_t handle = GetTimeMs() + ms;
    
    DLOG("handle: " << handle);
    
    TimerInfo info;
    info.wpTimer_ = spTimer;
    info.pTimer_  = spTimer.get();
    info.appData_ = 0;
    info.appDataEx_ = appData;
    info.useRaw_  = false;
    info.pFile_   = pFile;
    info.line_    = line;
    
    AddTimer(info, handle);
    
    return handle;
}

int64_t TimerServiceImpl::StartTimerEx(Timer* pTimer, int32_t ms, int32_t appData,
                                       const char* pFile, int line)
{
    pFile = (strrchr(pFile, _DIR_MARK_) ? strrchr(pFile, _DIR_MARK_) + 1 : pFile);

    int64_t handle = GetTimeMs() + ms;
    
    DLOG("handle: " << handle << " " << ms << " ms, appData: " << appData);
    
    TimerInfo info;
    info.pTimer_  = pTimer;
    info.appData_ = appData;
    info.appDataEx_ = NULL;
    info.useRaw_  = true;
    info.pFile_   = pFile;
    info.line_    = line;
    
    AddTimer(info, handle);
    
    return handle;
}

void TimerServiceImpl::StopTimer(Timer::Ptr spTimer, int64_t handle)
{
    RemoveTimer(spTimer.get(), handle);
}

void TimerServiceImpl::StopTimer(Timer* pTimer, int64_t handle)
{
    RemoveTimer(pTimer, handle);
}

void TimerServiceImpl::AddTimer(TimerInfo& rInfo, int64_t handle)
{
    bool b_wake = false;
    
    {
        MutexLock scoped(&lock_);
        // if pool is empty or new item has early timeout then
        // wake the thread up
        if (pool_.empty() || pool_.begin()->first > handle) {
            b_wake = true;
        }
        pool_.insert(std::pair<int64_t, TimerInfo>(handle, rInfo));
    }
    
    if (b_wake) {
        sem_.Post();
    }
}

void TimerServiceImpl::RemoveTimer(Timer* pTimer, int64_t handle)
{
    bool found = false;
    
    MutexLock scoped(&lock_);
    
    TimerPool::iterator it = pool_.find(handle);
    while (it != pool_.end() && it->first == handle) {
        if (it->second.pTimer_ == pTimer) {
            DLOG("handle " << handle << " cancelled");
            pool_.erase(it);
            found = true;
            break;
        }
        it++;
    }
    
    if (!found) {
        WLOG("Failed to stop handle: " << handle);
    }
}

void TimerServiceImpl::Run()
{
    TimerInfo timer;
    
    while (running_) {
        bool expired    = false;
        int  sleep_time = INFINITE;
        
        {
            MutexLock scoped(&lock_);
            if (!pool_.empty()) {
                TimerPool::iterator it = pool_.begin();
                
                int64_t curr_time   = GetTimeMs();
                int64_t expire_time = it->first;
                
                if (expire_time <= curr_time) {
                    
                    timer   = it->second;
                    expired = true;
                    
                    int64_t late = curr_time - expire_time;
                    if (late > 100) {
                        WLOG("timer expired " << late <<
                             " ms late (elem " << pool_.size() << ", " <<
                             timer.pFile_ << ":" << timer.line_ << ")");
                    }
                    
                    pool_.erase(it);
                }
                else {
                    sleep_time = int(expire_time - curr_time);
                }
            }
        }
        
        if (expired) {
            int64_t start_time = GetTimeMs();
            // if weak pointer is not available then use raw pointer
            if (timer.useRaw_) {
                if (timer.pTimer_) {
                    if (timer.appDataEx_)
                    {
                        timer.pTimer_->OnTimerEx(timer.appDataEx_);
                    }
                    else
                    {
                        timer.pTimer_->OnTimer(timer.appData_);
                    }
                }
            }
            else if (Timer::Ptr sp_timer = timer.wpTimer_.lock()) {
                if (timer.appDataEx_)
                {
                    sp_timer->OnTimerEx(timer.appDataEx_);
                }
                else
                {
                    sp_timer->OnTimer(timer.appData_);
                }
            }
            int64_t time_took = GetTimeMs() - start_time;
            if (time_took > 100) {
                WLOG("Timer thread was delayed by caller by " <<
                     time_took << " ms (" << timer.pFile_ << ":" <<
                     timer.line_ << ")");
            }
        }
        else {
            DLOG("Timer waiting for " << sleep_time << " ms");
            sem_.Wait(sleep_time);
        }
    }
    
    MLOG("timer thread leaving");
    
    // signal done
    finish_.Post();
}

} // namespace fuze