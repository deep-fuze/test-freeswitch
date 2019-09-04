//
//  Log.h
//  FuzeTransport
//
//  Created by Tim Na on 11/14/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef _FUZE_DEBUG_H_
#define _FUZE_DEBUG_H_

#include <Transport.h> // for SeverityType exposure..
#include <MutexLock.h>
#include <cassert>
#include <Thread.h>
#include <string.h>
#include <stdlib.h>

#ifdef LOG_FILE
#include <fstream>
#endif

namespace fuze
{

// extern
extern int32_t  gDebugLevel;
extern uint64_t gDebugArea;
    
// Define DEBUG AREA
const uint64_t ALL_ON   = 0xffffffffffffffffULL;
const uint64_t ALL_OFF  = 0ULL;

const uint64_t AREA_LIB = 0x0000000000000001ULL; // LibEvent
const uint64_t AREA_COM = 0x0000000000000002ULL; // Common
const uint64_t AREA_UDP = 0x0000000000000004ULL; // UDP
const uint64_t AREA_TCP = 0x0000000000000008ULL; // TCP
const uint64_t AREA_BUF = 0x0000000000000010ULL; // Buffer
const uint64_t AREA_APP = 0x0000000000000020ULL; // APP

//
// Time print function
//
char* T();
    
//
// Define DEBUG MACRO
//
// Use print to force log witout condition
#ifdef WIN32
#define _DIR_MARK_ '\\'
#define __FUZE_FUNC__ (strrchr(__FUNCTION__, ':') ? strrchr(__FUNCTION__, ':') + 1 : __FUNCTION__)
#else 
#define _DIR_MARK_ '/'
#define __FUZE_FUNC__ __FUNCTION__
#endif
    
#define __FUZEFILE__ (strrchr(__FILE__, _DIR_MARK_) ? strrchr(__FILE__, _DIR_MARK_) + 1 : __FILE__)
    
#define PRINT(A,B) { dout().Lock(); dout() << __FUZEFILE__ << ":" << __LINE__ << "  " << A << B; dout().EndLine(); dout().Unlock(); }
    
#define DEBUG_OUT(A,B,C) if (A <= gDebugLevel && (B & gDebugArea)) PRINT(A,C)
    
// define different level for application if they want to us _LOG_ macro
#define ELOG(A) _LOG_(LEVEL_ERROR, A)
#define MLOG(A) _LOG_(LEVEL_MSG, A)
#define WLOG(A) _LOG_(LEVEL_WARN, A)
#define DLOG(A) _LOG_(LEVEL_DEBUG, A)
    
// generic print
#define _DLOG_(A) DEBUG_OUT(LEVEL_DEBUG, AREA_COM, __FUZE_FUNC__ << ": " << A);
#define _MLOG_(A) DEBUG_OUT(LEVEL_MSG, AREA_COM, __FUZE_FUNC__ << ": " << A);
#define _WLOG_(A) DEBUG_OUT(LEVEL_WARN, AREA_COM, __FUZE_FUNC__ << ": " << A);
#define _ELOG_(A) DEBUG_OUT(LEVEL_ERROR, AREA_COM, __FUZE_FUNC__ << ": " << A);
    
// Class to print in hex format
struct Hex;

// Implementing own debug stream out
class DebugOut : private NotCopyable
{
public:
    DebugOut();
    virtual ~DebugOut();

    class Endline {};

    void SetTraceObserver(TransportTraceObserver* pObserver, bool bPrefix = false);
    void EnableFuzeLog();
    
    DebugOut& operator<<(SeverityType eType);
    DebugOut& operator<<(const bool input);
    DebugOut& operator<<(const char input);
    DebugOut& operator<<(const unsigned char input);
    DebugOut& operator<<(const char* pInput);
    DebugOut& operator<<(const unsigned short input);
    DebugOut& operator<<(const short input);
    DebugOut& operator<<(const unsigned int input);
    DebugOut& operator<<(const int input);
    DebugOut& operator<<(const unsigned long input);
    DebugOut& operator<<(const long input);
    DebugOut& operator<<(const long long input);
    DebugOut& operator<<(const unsigned long long input);
    DebugOut& operator<<(const float input);
    DebugOut& operator<<(const double input);

    DebugOut& operator<<(const std::string& rString);
    DebugOut& operator<<(const Hex& rHex); 
    DebugOut& operator<<(void* pPtr);

    void EndLine();

#if defined(WIN32)
    DebugOut& operator<<(const wchar_t* pInput) {
        if (pInput) { flush(); OutputDebugStringW(pInput); }
        return *this;
    }
#endif

    inline void Lock()   { return lock_.Lock(); }
    inline void Unlock() { return lock_.Unlock(); }

private:

    static const int32_t BUFFER_SIZE = 4096;
    static const int32_t DIGIT_SPACE = 20; // for digit space
    static const int32_t CRLF_NULL   = 3;  // space for CR LF NULL char

    void flush();
    void record(int32_t bytes);
    void validate(int32_t len = DIGIT_SPACE) { if (left_ < len) flush(); }

    MutexLock     lock_;
    
    char*         pBuf_; // char buffer to write debug message to
    int32_t       WI_;   // Write Index: indication for next byte to write
    int32_t       left_; // Buffer Available
    int32_t       size_;

    SeverityType  type_;
    
    bool                     bFuzeLog_; // use fuze log
    TransportTraceObserver*  pObserver_;
#ifdef LOG_FILE
    std::ofstream   m_OutFile;
#endif
};

// Hex class
struct Hex
{
    const uint8_t*  pPos_;
    int32_t         size_;
    int32_t         unit_;
    uint64_t        temp_;

    Hex(const uint8_t* pPos, int32_t length = 16, int32_t format = 4);
    Hex(int32_t num);
    Hex(uint32_t num);
    Hex(int16_t num);
    Hex(uint16_t num);
};

inline DebugOut& dout()
{
    static DebugOut s_debug_out;
    return s_debug_out;
}

} // namespace fuze

#endif // _FUZE_DEBUG_H_
