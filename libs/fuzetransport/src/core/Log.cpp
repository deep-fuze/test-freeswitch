//
//  Log.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/14/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#include <Log.h>

#ifndef WIN32
#include <sys/time.h> // gettimeofday
#include <iostream>   // flush
#include <cstdlib>
#include <cstring>
#else
#include <mmsystem.h>
#endif

#ifdef __APPLE__ // for GetTimeMs()
#include <TargetConditionals.h>
#include <mach/mach_time.h>
#endif

#ifdef __linux__
#include <stdio.h> // sprintf
#include <arpa/inet.h> // hton stuff
#endif

#ifndef FREE_SWITCH
// integrating fuze log
#include <fuze/core/Log.h>
#include <fuze/core/Once.h>
#include <fuze/core/FuzeString.h>
#endif

namespace fuze
{
    
int32_t  gDebugLevel = LEVEL_MSG;
uint64_t gDebugArea  = ALL_ON;

#ifndef FREE_SWITCH
using namespace fuze::core;

static Log::Pointer g_log;
static Once::Handle g_logOnce = FUZE_CORE_ONCE_INITIALIZER;

void make_app_logger()
{
    g_log = Log::getLog("fuze.tp");
    g_log->showFileAndLine(false);
    g_log->showProcessInfo(true);
    g_log->showDate(true);
}

Log::Pointer get_log()
{
    Once::call(g_logOnce, &make_app_logger);
    return g_log;
}
#endif
    
//
// Method: Time
// Remark: this function use static buffer, must be protected by mutex
//
char* T()
{
    const int32_t SIZE = 64;
    static char buf[SIZE];

#if defined(WIN32)
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    sprintf_s(buf, "%02d:%02d:%02d.%03d ",
            lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
#else
    timeval tv;
    gettimeofday(&tv, 0);
    time_t t = tv.tv_sec;
    strftime(buf, SIZE, "%T.", localtime(&t));
    sprintf(buf, "%s%03d ", buf, (int)tv.tv_usec/1000); // cast as linux complains
#endif    

    return buf;
}

int64_t GetTimeMs()
{
    int64_t result = 0;
#ifdef WIN32
    static volatile LONG last_time_get_time = 0;
    static volatile int64_t num_wrap_time_get_time = 0;
    volatile LONG* last_time_get_time_ptr = &last_time_get_time;
    DWORD now = timeGetTime();
    // Atomically update the last gotten time
    DWORD old = InterlockedExchange(last_time_get_time_ptr, now);
    if (now < old) {
        // If now is earlier than old, there may have been a race between
        // threads.
        // 0x0fffffff ~3.1 days, the code will not take that long to execute
        // so it must have been a wrap around.
        if (old > 0xf0000000 && now < 0x0fffffff) {
            num_wrap_time_get_time++;
        }
    }
    result = now + (num_wrap_time_get_time << 32);
#elif defined(__linux__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    result = 1000000000LL * static_cast<int64_t>(ts.tv_sec) +
             static_cast<int64_t>(ts.tv_nsec);
	result /= 1000000;
#elif defined(__APPLE__)
    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
        // Get the timebase if this is the first time we run.
        // Recommended by Apple's QA1398.
        kern_return_t retval = mach_timebase_info(&timebase);
        if (retval != KERN_SUCCESS) {
            // TODO(wu): Implement CHECK similar to chrome for all the platforms.
            // Then replace this with a CHECK(retval == KERN_SUCCESS);
            __builtin_trap();
        }
    }
    // Use timebase to convert absolute time tick units into nanoseconds.
    result = mach_absolute_time() * timebase.numer / timebase.denom;
    result /= 1000000;
#else // all other platform
    struct timeval tv;
    gettimeofday(&tv, NULL);
    result.ticks_ = 1000000LL * static_cast<int64_t>(tv.tv_sec) +
    static_cast<int64_t>(tv.tv_usec);
#endif
    return result;
}

//---------------------------------------------------------------------------------
// Method: Constructor
// Remark:
//---------------------------------------------------------------------------------
DebugOut::DebugOut()
    : size_(BUFFER_SIZE)
    , WI_(0)
    , type_(LEVEL_DEBUG)
    , pObserver_(0)
    , bFuzeLog_(false)
{
    pBuf_ = (char*)std::malloc(size_);
    left_ = size_ - CRLF_NULL;

#ifdef LOG_FILE
    std::string file_path;

    const char* p_path = std::getenv("LOGPATH");

    if (p_path) {
        file_path = p_path;
#ifdef WIN32
        file_path += "\\";
#else
        file_path += "/";
#endif
    }

    const int32_t SIZE = 32;
    char buf[SIZE];

    time_t t = time(0);       
    strftime(buf, SIZE, "log-%Y-%m-%d.txt", localtime(&t));
    file_path += buf;
    
    m_OutFile.open(file_path.c_str(), std::ios::app);
#endif
    
    operator<<("(build date: ") << __DATE__ << " " << __TIME__
            << ") log started\n";
}

//---------------------------------------------------------------------------------
// Method: Destructor
//---------------------------------------------------------------------------------
DebugOut::~DebugOut()
{
    operator<<("(build date: ") << __DATE__ << " " << __TIME__
            << ") log ended\n";
    flush();

    free(pBuf_);
    
#ifdef LOG_FILE
    m_OutFile.close();
#endif
}

void DebugOut::SetTraceObserver(TransportTraceObserver* pObserver, bool bPrefix)
{
    lock_.Lock();
    pObserver_ = pObserver;
    lock_.Unlock();
    
    if (pObserver) {
        operator<<("transport (build date: ")
                << __DATE__ << " " << __TIME__
                << ")\n";
    }
}

void DebugOut::EnableFuzeLog()
{
    bFuzeLog_ = true;
}
    
//---------------------------------------------------------------------------------
// Method: operator<<(SeverityTYpe)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(SeverityType eType)
{
    type_ = eType;
    
    if (!bFuzeLog_ && !pObserver_) {
        operator<<(T());
        switch (eType)
        {
        case LEVEL_ERROR: operator<<("[ERR] "); break;
        case LEVEL_MSG:   operator<<("[MSG] "); break;
        case LEVEL_WARN:  operator<<("[WRN] "); break;
        case LEVEL_DEBUG: operator<<("[DBG] "); break;
        case LEVEL_MAX:   operator<<("[MAX] "); break;
        }
    }

    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const bool input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const bool input)
{
    const char* p = (input ? "True" : "False");
    return (operator<<(p));
}
    
//---------------------------------------------------------------------------------
// Method: operator<<(const char input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const char input)
{
    // If we are short of space then just flush it so we have more buffer to write on
    validate(1);

    pBuf_[WI_++] = input;
    left_ -= 1;

    return *this;
}
        
//---------------------------------------------------------------------------------
// Method: operator<<(const unsigned char input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const unsigned char input)
{
    return (operator<<((unsigned short)input));
}

//---------------------------------------------------------------------------------
// Method: operator<<(const char* pChar)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const char* pInput)
{
    if (!pInput) return *this;

    int32_t input_len  = (int32_t)strlen(pInput);
    int32_t copy_size  = (left_ > input_len ? input_len : left_);
    int32_t copy_index = 0;

    while (input_len > 0)
    {
        memcpy(pBuf_ + WI_, pInput + copy_index, copy_size);

        WI_      += copy_size;
        left_    -= copy_size;
        input_len -= copy_size;

        // only if current input char is overflowing then flush the buffer
        if (input_len > 0)
        {       
            flush();
            copy_index += copy_size;
            copy_size = (left_ > input_len ? input_len : left_);
        }
    }

    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const short input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const short input)
{
    // If we are short of space then just flush it so we have more buffer to write on
    validate();

    // sprintf returns the number of bytes stored in buffer, not counting 
    // the terminating null character.
    record(sprintf(&pBuf_[WI_], "%i", input));

    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const unsigned short input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const unsigned short input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%u", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const int input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const int input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%i", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const unsigned int input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const unsigned int input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%u", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const unsigned long input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const unsigned long input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%lu", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const long input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const long input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%li", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const long input)
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const long long input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%lld", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const long input)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const unsigned long long input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%llu", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const float input)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const float input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%4.2f", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const double input)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const double input)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%4.2f", input));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(const std::string& rString)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const std::string& rString)
{
    return operator<<(rString.c_str());
}

//---------------------------------------------------------------------------------
// Method: operator<<(const Hex& rHex)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(const Hex& rHex)
{
    if (rHex.size_ > 0) {
        validate( rHex.size_ * 5 );
        for (int32_t i = 0; i < rHex.size_; ++i) {
            if ((i != 0) && (rHex.unit_ != 0) && (i % rHex.unit_ == 0)) {
                pBuf_[WI_++] = ' ';
                left_ -= 1;
            }
            record(sprintf(&pBuf_[WI_], "%02x", rHex.pPos_[i]));
            validate();
        }
    }

    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(void* pPtr)
// Remark:
//---------------------------------------------------------------------------------
DebugOut& DebugOut::operator<<(void* pPtr)
{
    validate();
    record(sprintf(&pBuf_[WI_], "%p", pPtr));
    return *this;
}

//---------------------------------------------------------------------------------
// Method: operator<<(int32_t bytes)
// Remark:
//---------------------------------------------------------------------------------
void DebugOut::record(int32_t bytes)
{
    if (bytes != -1) {
        WI_ += bytes;
        left_ -= bytes;         
    }
}

//---------------------------------------------------------------------------------
// Method: operator<<(EndLine& rEndl)
// Remark:
//---------------------------------------------------------------------------------
void DebugOut::EndLine()
{
    if (!bFuzeLog_ && !pObserver_) {
        //pBuf_[WI_++] = '\r'; // iOS treats this as new line
        pBuf_[WI_++] = '\n';
    }

    flush();
}

//---------------------------------------------------------------------------------
// Method: flush
// Remark:
//---------------------------------------------------------------------------------
void DebugOut::flush() try
{
    pBuf_[WI_] = '\0';

#ifndef FREE_SWITCH
    if (bFuzeLog_) {
        switch (type_)
        {
        case LEVEL_DEBUG: FUZE_LOG_TRACE(get_log(), "%s", pBuf_); break;
        case LEVEL_MSG:   FUZE_LOG_INFO(get_log(), "%s", pBuf_);  break;
        case LEVEL_WARN:  FUZE_LOG_WARN(get_log(), "%s", pBuf_);  break;
        case LEVEL_ERROR: FUZE_LOG_ERROR(get_log(), "%s", pBuf_); break;
        default:;
        }
    }
#endif
    
    if (pObserver_) {
        pObserver_->OnTransportTrace(type_, pBuf_);
    }

    // if neither then print out in console by default
    if (!bFuzeLog_ && !pObserver_) {
#ifdef WIN32
        OutputDebugStringA(pBuf_);
#else
    #ifdef LOG_FILE
        m_OutFile << pBuf_ << std::flush;
    #else
        std::cout << pBuf_ << std::flush;
    #endif
#endif
    }
    
    left_ = size_ - CRLF_NULL;
    WI_   = 0;
}
catch (...) {} // in case something goes wrong catch it..

Hex::Hex(const uint8_t* pPos, int32_t length, int32_t format)
    : pPos_(pPos), size_(length), unit_(format), temp_(0)
{
}
    
Hex::Hex(int32_t num)
    : pPos_((uint8_t*)&temp_), size_(4), unit_(4), temp_((uint64_t)num)
{
    temp_ = htonl((long)temp_);
    pPos_ += 4;
}
    
Hex::Hex(uint32_t num)
    : pPos_((uint8_t*)&temp_), size_(4), unit_(4), temp_((uint64_t)num)
{
    temp_ = htonl((long)temp_);
    pPos_ += 4;
}

Hex::Hex(int16_t num)
    : pPos_((uint8_t*)&temp_), size_(4), unit_(4), temp_((uint64_t)num)
{
    temp_ = htons((short)temp_);
    pPos_ += 6;
}

Hex::Hex(uint16_t num)
    : pPos_((uint8_t*)&temp_), size_(4), unit_(4), temp_((uint64_t)num)
{
    temp_ = htons((short)temp_);
    pPos_ += 6;
}
    
} // namespace fuze

void fuze_ext_log(int level, const char* format, ...)
{
#ifndef FREE_SWITCH
    va_list va;
    va_start(va, format);
    const string& msg = fuze::String::vformat(format, va);
    va_end(va);
    
    switch (level)
    {
        case 4: FUZE_LOG_TRACE(fuze::get_log(), "%s", msg.c_str()); break;
        case 3: FUZE_LOG_INFO(fuze::get_log(), "%s", msg.c_str());  break;
        case 2: FUZE_LOG_WARN(fuze::get_log(), "%s", msg.c_str());  break;
        case 1: FUZE_LOG_ERROR(fuze::get_log(), "%s", msg.c_str()); break;
        default:;
    }
#endif
}

