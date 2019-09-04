//
//  TcpCore.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/21/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <TcpCore.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, log_ << __FUZE_FUNC__ << ": " << B)

#ifndef WIN32
#include <errno.h>
#include <string.h>
#define EVUTIL_ERR_RW_RETRIABLE(e)			\
        ((e) == EINTR || (e) == EAGAIN)
#else
#define EVUTIL_ERR_RW_RETRIABLE(e)          \
        ((e) == WSAEWOULDBLOCK ||           \
        (e) == WSAEINTR)
#endif

namespace fuze {
    
RateLimiter::RateLimiter(TcpCore* pCore)
    : pCore_(pCore)
    , pRateEvent_(0)
    , mtu_(MTU_SIZE)
{
    Reset();
}

void RateLimiter::Reset()
{
    allowedBytes_ = mtu_;
    startTime_    = 0;
    
    if (pRateEvent_) {
        event_free(pRateEvent_);
        pRateEvent_ = 0;
    }
    
    rateAdded_ = false;
}

void RateLimiter::ClearEvent()
{
    if (rateAdded_ && pRateEvent_) {
        event_del(pRateEvent_);
        rateAdded_ = false;
    }
}

bool RateLimiter::IsOn()
{
    return true;
}
    
bool RateLimiter::IsLimiting()
{
    return rateAdded_;
}
    
long RateLimiter::GetAllowedBytes()
{
    return allowedBytes_;
}

void RateLimiter::SetSentBytes(long sent)
{
    if (allowedBytes_ > sent) {
        allowedBytes_ -= sent;
    }
    else { // shouldn't be happening but won't hurt
        allowedBytes_ = 0;
    }
}
    
void RateLimiter::SetMTU(long mtu)
{
    allowedBytes_ = mtu_ = mtu;
}

bool RateLimiter::Continue()
{
    int64_t curr_time = GetTimeMs();
    
    if (startTime_ == 0) {
        startTime_ = curr_time;
    }
    
    if (curr_time - startTime_ > RATE_PERIOD) {
        _DLOG_("Reset AllowedBytes " << allowedBytes_ << "B -> " <<
               mtu_ << "B as " << curr_time -startTime_ << "ms passed");
        allowedBytes_ = mtu_;
        startTime_ = curr_time;
    }
 
    bool b_continue = (allowedBytes_ != 0);
    
    // trigger RateEvent if it is not allowed to send more
    if (!b_continue) {
        if (!pRateEvent_) {
            if (TransportImpl* p = TransportImpl::GetInstance()) {
                rateAdded_ = p->CreateEvent(pRateEvent_,
                                            pCore_->rCoreUser_.Socket(),
                                            EV_TIMEOUT|EV_PERSIST,
                                            OnRateEvent, pCore_, RATE_PERIOD);
            }
        }
        else {
            if (!rateAdded_) {
                timeval time_out = { 0, RATE_PERIOD*1000 };
                rateAdded_ = (event_add(pRateEvent_, &time_out) == 0);
            }
        }
        
        // now allow it again to write after we come back
        allowedBytes_ = mtu_;
        startTime_ = curr_time + RATE_PERIOD; // update the time now
    }
    
    return b_continue;
}
    
void RateLimiter::OnRateEvent(evutil_socket_t socket, short what, void *pArg)
{
    if (TcpCore* p = reinterpret_cast<TcpCore*>(pArg)) {
        try {
            if (what & EV_TIMEOUT) {
                p->OnWriteEvent();
            }
        }
        catch (std::exception& ex) {
            _ELOG_("exception - " << ex.what());
        }
        catch (...) {
            _ELOG_("unknown exception");
        }
    }
}

TcpCore::TcpCore(TcpCoreUser& rUser)
    : rCoreUser_(rUser)
    , pReadEvent_(0)
    , pWriteEvent_(0)
    , writeAdded_(false)
    , byteSent_(0)
    , byteRecv_(0)
    , readTimeout_(0)
    , rateLimiter_(this)
    , sendQSize_(0)
    , sendBufSize_(0)
    , sendRetryCnt_(0)
{
    log_[0] = 0;
}

TcpCore::~TcpCore()
{
    // do not call Reset as other static variable may have
    // been freed such as RawBuffer's global pool
    if (pReadEvent_)  event_free(pReadEvent_);
    if (pWriteEvent_) event_free(pWriteEvent_);
}

void TcpCore::Reset()
{
    // protect against race condition with application thread
    MutexLock scoped(&qlock_);
    
    if (pReadEvent_)  event_free(pReadEvent_);
    if (pWriteEvent_) event_free(pWriteEvent_);
    
    pReadEvent_  = 0;
    pWriteEvent_ = 0;
    
    sendBuf_.reset();
    recvBuf_.reset();
    byteSent_    = 0;
    byteRecv_    = 0;
    writeAdded_  = false;
    
    rateLimiter_.Reset();
    
    queue<Buffer::Ptr> emptyQ;
    swap(sendQ_, emptyQ);
    
    readTimeout_  = 0;
    sendQSize_    = 0;
    sendBufSize_  = 0;
    sendRetryCnt_ = 0;
    
    log_[0] = 0;    
}
    
bool TcpCore::StartReceive()
{
    if (pReadEvent_) {
        ELOG("already started receiving data");
        return true;
    }

    bool bResult = false;
    
    if (TransportImpl* p = TransportImpl::GetInstance()) {

        short what = EV_READ|EV_PERSIST;
        
        if (readTimeout_ > 0) {
            MLOG("Setting " << readTimeout_ << " ms timeout");
            what |= EV_TIMEOUT;
        }
        
        bResult = p->CreateEvent(pReadEvent_,
                                 rCoreUser_.Socket(),
                                 what,
                                 OnLibEvent,
                                 this,
                                 readTimeout_);
    }
    
    return bResult;
}

void TcpCore::SetReadTimeout(uint16_t timeout)
{
    readTimeout_ = timeout;
}

void TcpCore::SetMaxBandwidth(uint16_t maxKbps)
{
    // convert max kbps into bytes per 10 ms
    long max_bytes = maxKbps * RateLimiter::RATE_PERIOD / 8;
    
    MLOG("Setting max " << maxKbps << "kbps bandwidth (" << max_bytes <<
         "B per " << RateLimiter::RATE_PERIOD << "ms )");
    
    rateLimiter_.SetMTU(max_bytes);
}
    
void TcpCore::OnLibEvent(evutil_socket_t socket, short what, void *pArg)
{
    if (TcpCore* p = reinterpret_cast<TcpCore*>(pArg)) {
        try {
            if (what & EV_READ) {
                p->OnReadEvent();
            }
            if (what & EV_WRITE) {
                p->OnWriteEvent();
            }
            if (what & EV_TIMEOUT) {
                p->OnTimeoutEvent();
            }
        }
        catch (std::exception& ex) {
            _ELOG_("exception - " << ex.what());
        }
        catch (...) {
            _ELOG_("unknown exception");
        }
    }
}
    
void TcpCore::OnWriteEvent()
{
    long tcp_sent = -1;
    
    do {
        if (!sendBuf_) {
            MutexLock scoped(&qlock_);
            if (sendQ_.empty()) {
                if (writeAdded_ && pWriteEvent_) {
                    event_del(pWriteEvent_);
                    writeAdded_ = false;
                }
                if (rateLimiter_.IsLimiting()) {
                    rateLimiter_.ClearEvent();
                }
                return;
            }
            
            sendBuf_ = sendQ_.front();
            sendQ_.pop();

            // keep track these for statistics
            sendBufSize_ = sendBuf_->size();
            sendQSize_  -= sendBufSize_;
        }
        
		// read buffer pointer and size to include header portion
        uint8_t* p_buf = sendBuf_->getBuf() + byteSent_;
        int32_t  size  = sendBuf_->size() - byteSent_;
        
        if (rateLimiter_.IsOn()) {
            long allowed = rateLimiter_.GetAllowedBytes();
            if (size > allowed) {
                size = allowed;
            }
        }
    
        // now we have data to send
		int flag = 0;
#ifdef MSG_NOSIGNAL // for linux to prevent SIGPIPE
		flag = MSG_NOSIGNAL;
#endif
        tcp_sent = ::send(rCoreUser_.Socket(), (char*)p_buf, size, flag);
        if (tcp_sent != -1) {
            byteSent_ += tcp_sent;
            sendBufSize_ -= tcp_sent;
            
            DLOG(tcp_sent << "B sent: [" <<
                 Hex(p_buf, (tcp_sent <= 30 ? (int)tcp_sent : 30)) << "]");
            
            if (byteSent_ == sendBuf_->size()) {
                DLOG("Completed sending " << byteSent_ << "B");
                sendBuf_.reset();
                byteSent_    = 0;
                sendBufSize_ = 0;
            }
            
            rCoreUser_.OnBytesSent((uint32_t)tcp_sent);
            
            if (rateLimiter_.IsOn()) {
                // check with rate limiter if we are allowed to continue
                rateLimiter_.SetSentBytes(tcp_sent);
                if (rateLimiter_.Continue() == false) {
                    DLOG("RateLimiter - stop after sending " << tcp_sent <<
                         "B (total " << byteSent_ << "B)");
                    // remove write event as rate limiter is not triggered
                    MutexLock scoped(&qlock_);
                    if (writeAdded_ && pWriteEvent_) {
                        event_del(pWriteEvent_);
                        writeAdded_ = false;
                    }
                    return;
                }
            }
        }
    } while (tcp_sent > 0);
    
    if (tcp_sent == -1)
    {
        int error = evutil_socket_geterror(rCoreUser_.Socket());
        if (EVUTIL_ERR_RW_RETRIABLE(error)) {
            DLOG("Retry send() later: " <<
                 evutil_socket_error_to_string(error));
            sendRetryCnt_++;
            // if we were limiting and reached socket buffer full
            // status then add write event back to get next libevent
            if (rateLimiter_.IsLimiting()) {
                // lock so that app thread can't add it same time
                MutexLock scoped(&qlock_);
                rateLimiter_.ClearEvent();
                if (!writeAdded_ && pWriteEvent_) {
                    event_add(pWriteEvent_, 0);
                    writeAdded_ = true;
                }
            }
        }
        else {
            WLOG(evutil_socket_error_to_string(error));
            // remove the write event so that we don't get it again
            {
                MutexLock scoped(&qlock_);
                if (writeAdded_ && pWriteEvent_) {
                    event_del(pWriteEvent_);
                    writeAdded_ = false;
                }
                if (rateLimiter_.IsLimiting()) {
                    rateLimiter_.ClearEvent();
                }
            }
            rCoreUser_.OnWriteError(error);
        }
    }
}

void TcpCore::ResetReadBuffer()
{
    DLOG("No more room in buffer " <<
         "(Offset: " << recvBuf_->getOffset() <<
         " size: " << recvBuf_->size() << "B" <<
         " byteRecv_: " << byteRecv_ << "B)");    
    
    // depends on how full the data is in buffer, assign
    // how big our buffer need to be
    uint32_t multiple = (byteRecv_+100)/BUFFER_SIZE + 1;
    uint32_t buf_size = BUFFER_SIZE * multiple;
    
    // if we ran out of buffer space and application hasn't
    // read all data then increase the buffer size, otherwise,
    // create Buffer with BUFFER_SIZE and copy the remainder
    
    // guard against misbehaving app
    if (buf_size > BUF_SIZE_LIMIT) {
        ELOG("BUF_SIZE_LIMIT passed - discard buffer");
        buf_size  = BUFFER_SIZE;
        byteRecv_ = 0;
    }
    
    // NOTE: we can't use memmove to be more efficient here
    //       as transport provided buffer to application
    //       can't be touched again by transport
    //
    Buffer::Ptr new_buf = Buffer::MAKE(buf_size);
    new_buf->setSize(buf_size-1); // reserve null space
    if (byteRecv_ > 0) {
        // if we have filled up the buffer and get a new buffer
        // copy the remaining data to new buffer
        DLOG("Adjusted buffer size: " << new_buf->size() <<
             "B, moved leftover " << byteRecv_ << "B");
        memcpy(new_buf->getBuf(), recvBuf_->getBuf(), byteRecv_);
    }
    
    recvBuf_ = new_buf;
}
    
void TcpCore::OnReadEvent()
{
    // this should be part of initialization code as reset is
    // deleting the buffer and we are trying to avoid shutdown
    // crash due to buffer deallocation.
    if (!recvBuf_) {
        recvBuf_= Buffer::MAKE(BUFFER_SIZE);
        recvBuf_->setSize(BUFFER_SIZE-1); // reserve null space
    }
    
    bool read_again = false;
    long read_bytes = 0;
    
    do {
        uint8_t* p_write   = recvBuf_->getBuf() + byteRecv_;
        uint32_t size_left = recvBuf_->size() - byteRecv_;
        
        // if we ran out of space then increase the buffer size
        if (size_left == 0) {
            
            ResetReadBuffer();
            
            p_write   = recvBuf_->getBuf() + byteRecv_;
            size_left = recvBuf_->size() - byteRecv_;
            
            if (size_left == 0) {
                ELOG("Available buffer size is still 0 after ResetReadBuffer");
                event_del(pReadEvent_);
                rCoreUser_.OnReadError(0);
                return;
            }
        }
        
        read_bytes = recv(rCoreUser_.Socket(), (char*)p_write, size_left, 0);
        if (read_bytes > 0) {
            
            rCoreUser_.OnBytesRecv((uint32_t)read_bytes);
            
            if ((uint32_t)read_bytes > size_left) {
                ELOG("socket recv() returned more than requested (req size:" <<
                     size_left << "B, actual read:" << read_bytes << "B)");
                event_del(pReadEvent_);
                rCoreUser_.OnReadError(0);
                return;
            }
            
            byteRecv_ += read_bytes;

            // always put NULL byte in the end for easier text message parsing
            // space is guaranteed as we reserved NULL space in allocation
            p_write[read_bytes] = 0;
            
            DLOG(read_bytes << "B (buffer " << size_left << "B) received: [" <<
                 Hex(p_write, (read_bytes <= 30 ? (int)read_bytes : 30)) << "]");

            // we want to feed the data as long as app accepts it
            uint32_t app_read = 0;
            
            do {
                Buffer::Ptr sp_copy = Buffer::makeShallowCopy(recvBuf_);
                
                sp_copy->setSize(byteRecv_);
                
                app_read = rCoreUser_.OnDataReceived(sp_copy);
                
                // it is possible that CoreUser may have been reset by ConnectionImpl
                // normally we use libevent thread to reset the connection but when
                // we replace transceiver, we reset the old one right away
                if (rCoreUser_.Socket() == INVALID_SOCKET) {
                    DLOG("TcpCoreUser is released during callback");
                    return;
                }
                
                if (app_read > 0) {
                    if (app_read > byteRecv_) {
                        ELOG("App read more than received (read " << app_read <<
                             "B vs available " << byteRecv_ << "B)");
                        event_del(pReadEvent_);
                        rCoreUser_.OnReadError(0);
                        return;
                    }
                    // subtract how much application read
                    byteRecv_ -= app_read;
                    recvBuf_->pull(app_read);
                }
            }
            while ((app_read != 0) && (byteRecv_ > 0));
        }
        
        // if last read filled the buffer than we may have more data in socket
        read_again = (read_bytes == size_left);
    }
    while (read_again);
    
    if (read_bytes == 0) {
        MLOG("Far end closed the connection");        
        event_del(pReadEvent_);
        rCoreUser_.OnDisconnect();
    }
    else if (read_bytes == -1) {
        int error = evutil_socket_geterror(rCoreUser_.Socket());
        if (EVUTIL_ERR_RW_RETRIABLE(error)) {
            DLOG("Retry recv() later: " <<
                 evutil_socket_error_to_string(error));
        }
        else {
            WLOG(evutil_socket_error_to_string(error));
            event_del(pReadEvent_);
            rCoreUser_.OnReadError(error);

            // most likely we will get write error after this
            // remove the write error so we won't get error again
            MutexLock scoped(&qlock_);
            if (writeAdded_ && pWriteEvent_) {
                event_del(pWriteEvent_);
                writeAdded_ = false;
            }
            if (rateLimiter_.IsLimiting()) {
                rateLimiter_.ClearEvent();
            }
        }
    }
}

void TcpCore::OnTimeoutEvent()
{
    rCoreUser_.OnReadTimeout();
}
    
void TcpCore::Send(Buffer::Ptr spBuf)
{    
    MutexLock scoped(&qlock_);
    
    sendQ_.push(spBuf);
    sendQSize_ += spBuf->size();
    
    // trigger write operation if not done yet for first time
    if (!pWriteEvent_) {
        if (TransportImpl* p = TransportImpl::GetInstance()) {
            writeAdded_ = p->CreateEvent(pWriteEvent_,
                                         rCoreUser_.Socket(),
                                         EV_WRITE|EV_PERSIST,
                                         OnLibEvent, this);
        }
    }
    else {
        // if rate limiter is not running and we don't have
        // write event added to libevent then do it
        if (!writeAdded_ && pWriteEvent_ && !rateLimiter_.IsLimiting()) {
            DLOG("Write event registered");
            event_add(pWriteEvent_, 0);
            writeAdded_ = true;
        }
    }
}

void TcpCore::GetSendQInfo(size_t& rNum, uint32_t& rBufSize)
{
    rNum     = sendQ_.size() + (sendBuf_ ? 1 : 0);
    rBufSize = sendQSize_ + sendBufSize_;
}
    
uint32_t TcpCore::GetSendRetryCount()
{
    uint32_t retry = sendRetryCnt_;
    // this is good for now as we only have libevent thread
    // modify and access this
    sendRetryCnt_ = 0;
    return retry;
}
    
} // namespace fuze