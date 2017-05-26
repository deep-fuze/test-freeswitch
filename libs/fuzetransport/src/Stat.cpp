//
//  Stat.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/24/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#include "Stat.h"
#include <ConnectionImpl.h>
#include <sstream>
#include <Log.h>

#ifdef __linux__
#include <cstring> // memset
#include <cmath>
#endif

namespace fuze {
    
StatData::StatData(const char* pUnit)
    : pUnit_(pUnit)
{
    Clear();
}

void StatData::Clear()
{
    memset(data_, 0, sizeof(data_));
    index_  = 0;
    seq_    = 0;
}

void StatData::SetData(uint16_t data)
{
    if (index_ < MAX_NUM) {
        seq_++;
        data_[index_++] = data;
    }
}

bool StatData::Display(ostringstream& rLog,
                       const char*    pLog,
                       const char*    pPrefix)
{
    bool result = false;
    
    if (index_ == 0) return false;
    
    bool b_print = false;
    uint32_t avg = 0;
    for (int i = 0; i < index_; ++i) {
        avg += data_[i];
        if (!b_print && data_[i]) {
            b_print = true;
        }
    }
    avg /= index_;
    uint32_t stddev = 0;
    for (int i = 0; i < index_; ++i) {
        int diff = data_[i] - avg;
        stddev += diff * diff;
    }
    stddev = static_cast<uint32_t>(std::sqrt((double)stddev/index_));
    
    if (b_print) {
        rLog << "\n " << pLog << pPrefix << "Avg: " << avg << pUnit_
             << " [StdDev: " << stddev << ", data(" << index_ << ")";
        
        for (int i = 0; i < index_; ++i) {
            rLog << " " << data_[i];
        }
        rLog << "]";
        result = true;
    }
    
    index_ = 0;
    
    return result;
}

Stat::Stat(ConnectionImpl* pConn)
    : pConn_(pConn)
    , local_(" kbps")
    , remote_(" kbps")
    , sendQ_("")
    , sendBuf_(" B")
    , sendRetry_("")
    , arrival_(" ms")
{
    log_[0] = 0;
    Clear();
}

void Stat::Clear()
{
    count_       = 0;
    bytes_       = 0;
    bytes2_      = 0;
    totalBytes_  = 0;
    lastTime_    = 0;
    lastArrival_ = 0;
    lastSent_    = 0;
    
    local_.Clear();
    remote_.Clear();
    sendQ_.Clear();
    sendBuf_.Clear();
    arrival_.Clear();
}

int Stat::AddBytes(uint32_t bytes, int64_t currTime)
{
    if (bytes) {
        ++count_;
        bytes_      += bytes;
        bytes2_     += bytes;
        totalBytes_ += bytes;
    }
    
    int64_t diff = currTime - lastTime_;
    
    // skip the first time
    if (lastTime_ == 0) {
        lastTime_ = currTime;
        return -1;
    }
    
    if (diff > PERIOD) {
        uint16_t rate = (uint16_t)(diff ? (bytes_*8)/(diff) : 0);
        
        local_.SetData(rate);
        
        if (pConn_) {
            size_t   q_size = 0;
            uint32_t q_buf_size = 0;
            pConn_->GetSendQInfo(q_size, q_buf_size);
            sendQ_.SetData((uint16_t)q_size);
            sendBuf_.SetData(q_buf_size);
            sendRetry_.SetData(pConn_->GetSendRetryCount());
        }
        
        if (local_.index_ >= DISPLAY_CNT) {
            std::ostringstream log;
            log << "local seq # " << local_.seq_-local_.index_
                << " ~ " << local_.seq_-1;
            
            if (!local_.Display(log, log_, "Local  ")) {
                log << " (" << bytes2_ << "B, total "
                    << totalBytes_ << "B, cnt " << count_<< ")";
            }
            bytes2_ = 0;
            
            remote_.Display(log, log_, "Remote ");
            arrival_.Display(log, log_, "Arrival ");
            sendQ_.Display(log, log_, "Tx Queue #   ");
            sendBuf_.Display(log, log_, "Tx Buf Size  ");
            sendRetry_.Display(log, log_, "Tx Retry Cnt ");
            DEBUG_OUT(LEVEL_MSG, AREA_COM, log_ << log.str());
        }
        
        bytes_    = 0;
        lastTime_ = currTime;
        
        return rate;
    }
    
    return -1;
}

} // namespace fuze
