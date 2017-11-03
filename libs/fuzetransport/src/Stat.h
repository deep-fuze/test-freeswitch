//
//  Stat.h
//  FuzeTransport
//
//  Created by Tim Na on 2/24/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef Fuze_Stat_hpp
#define Fuze_Stat_hpp

#include <TransportImpl.h>

namespace fuze {

using std::ostringstream;

struct StatData
{
    static const uint16_t MAX_NUM = 200;
    
    uint16_t     data_[MAX_NUM];
    uint16_t     index_;
    uint32_t     seq_;
    const char*  pUnit_;
    
    StatData(const char* pUnit);
    
    void Clear();
    void SetData(uint16_t data);
    bool Display(ostringstream& rLog,
                 const char*    pLog,
                 const char*    pPrefix);
};

struct Stat
{
    static const int64_t  PERIOD      = 1000; // 1 seconds
    static const uint16_t DISPLAY_CNT = 10;
    static const uint8_t  TYPE_SEND   = 0;
    static const uint8_t  TYPE_RECV   = 1;
    
    uint32_t  count_;
    uint32_t  totalCount_;
    int64_t   bytes_;
    int64_t   bytes2_;      // track intermittent usage
    int64_t   totalBytes_;
    int64_t   lastTime_;
    char      log_[64];
    
    StatData  local_;       // local bandwidth
    StatData  cntStat_;     // count stat
    StatData  remote_;      // remote bandwidth
    StatData  sendQ_;       // sendQ_ size
    StatData  sendBuf_;     // buffer size to send
    StatData  sendRetry_;   // retry (full socket buffer)
    StatData  arrival_;     // jitter of receiving stat
    int64_t   lastArrival_; // timestamp of remote report
    int64_t   lastSent_;    // timestamp of our report
    MutexLock lock_;        // when app uses direct send API
    
    ConnectionImpl* pConn_; // sendStat on sendQ Info
    
    // set ConnectionImpl for report
    Stat(ConnectionImpl* pConn = 0);
    
    void Clear();
    
    // Add bytes so that we can measure usage
    // returns true when rate and count are available
    bool AddBytes(uint32_t  bytes, int64_t   currTime,
                  uint16_t& rRate, uint16_t& rCount);
};

} // namespace fuze

#endif /* Fuze_Stat_hpp */
