//
//  TransportIf.cpp
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/16/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <string.h>
#include <map>
#include <event2/util.h>

#include "Transport_c.h"
#include "Transport.h"
#include "TransportEvent.h"
#include "MutexLock.h"
#include "Queue.h"
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "[" << __FUZE_FUNC__ << ":" << __LINE__ << "] " << B)

using namespace fuze;
using fuze_shared_ptr;
#if defined(__linux__) && !defined(__ANDROID_API__)
using namespace __gnu_cxx;
#endif
using std::map;
using std::pair;
using std::make_pair;

/* Begin: Static Declarations */

typedef enum
{
    SWITCH_LOG_DEBUG = 7,
    SWITCH_LOG_INFO = 6,
    SWITCH_LOG_NOTICE = 5,
    SWITCH_LOG_WARNING = 4,
    SWITCH_LOG_ERROR = 3,
    SWITCH_LOG_CRIT = 2,
    SWITCH_LOG_ALERT = 1,
    SWITCH_LOG_CONSOLE = 0,
} freeswitch_log_level_t;

static freeswitch_log_level_t log_type[LEVEL_MAX] = {};
static ConnectionType conn_type[CONN_MAX] = {};

rate_cb_t g_rate_callback = 0;

void fuze_transport_register_rate_cb(rate_cb_t rate_cb)
{
    MLOG("Rate callback set");
    g_rate_callback = rate_cb;
}

struct connection_wrap_t
{
    connection_type_t     conn_type_;
    Connection::Ptr       conn_;
    FuzeQ<TransportEvent> evq_;
    __sockaddr_t          last_from_addr_;

    uint16_t rateKbps[4];
    uint16_t arrivedTime[4];

    size_t ignore_size;
};

/* End: Static Declarations */

/* Begin: C++*/
class TransportPoll : public ConnectionObserver
{
public:
    //Observer interface
    virtual void OnDataReceived(void* pContext, Buffer::Ptr spBuffer);
    virtual void OnEvent(void* pContext, EventType eType, const string& rReason);
    virtual void OnRateData(void*    pContext,
                            RateType type,
                            uint16_t rateKbps,
                            uint16_t arrivedTime);
    static TransportPoll& GetInstance() { return inst; }
    
private:
    static TransportPoll inst;
};

TransportPoll TransportPoll::inst;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

void TransportPoll::OnRateData(void*    pContext,
                               RateType type,
                               uint16_t rateKbps,
                               uint16_t arrivedTime) {
    
    if (g_rate_callback) {
        g_rate_callback(pContext, type, rateKbps, arrivedTime);
    }
    else {
        connection_wrap_t *conn_wrap = static_cast<connection_wrap_t *> (pContext);
        if (conn_wrap) {
            conn_wrap->rateKbps[type-RT_LOCAL_SEND] = rateKbps;
            conn_wrap->arrivedTime[type-RT_LOCAL_SEND] = arrivedTime;
        }
    }
}


void TransportPoll::OnDataReceived(void* pContext, Buffer::Ptr spBuffer)
{
    if (pContext && spBuffer) {
        
        connection_wrap_t *conn_wrap = static_cast<connection_wrap_t *> (pContext);
        
        TransportEvent::Ptr te(new TEData(spBuffer));

        string IP;
        uint16_t port;
        bool remChanged;
        Buffer::Ptr rdBuf = te->Data(IP, port, remChanged);

        if (rdBuf) {
            if (conn_wrap->ignore_size != 0) {
                if (rdBuf->size() < conn_wrap->ignore_size) {
                    return;
                }
            }

#ifdef COPY_TO_BUFFER
            if (remChanged == true) {
                if (!evutil_inet_pton(AF_INET, IP.c_str(),
                                      &(conn_wrap->last_from_addr_.sa.sin.sin_addr))) {
                    te->len = 0;
                }
            }
            te->len = MIN(rdBuf->size(), 1500);
            memcpy(te->buffer, rdBuf->getBuf(), te->len);
#endif

            conn_wrap->evq_.InsertNode(te);
            int qsize = conn_wrap->evq_.Size();

            if (qsize >= 2000) { // roughly 40 seconds delay then remove all
                string lIp;
                uint16_t lPort;
                conn_wrap->conn_->GetLocalAddress(lIp, lPort);
                MLOG("ALERT: High Event-Queue size: " << qsize << " on " <<
                     lIp.c_str() << ":" << lPort << " - flushing the Event-Queue");
                conn_wrap->evq_.Clear();
            }
        }
    }
    else {
      ELOG("Invalid Context or Buffer. Conext=" << (int64_t)pContext);
    }
}

void TransportPoll::OnEvent(void* pContext, EventType eType, const string& rReason)
{
    if (pContext) {
        
        connection_wrap_t *conn_wrap = static_cast<connection_wrap_t *> (pContext);
        
        TransportEvent::Ptr te(new TEConnEvent(eType));
        conn_wrap->evq_.InsertNode(te);
        int qsize = conn_wrap->evq_.Size();
        if (qsize && qsize % 1024 == 0) {
            string lIp;
            uint16_t lPort;
            conn_wrap->conn_->GetLocalAddress(lIp, lPort);
            MLOG("ALERT: High Event-Queue size: " << qsize << " on " << lIp.c_str() << ":" << lPort);
            if (qsize >= 500000) {
                MLOG("Flushing the Event-Queue.");
                while (conn_wrap->evq_.GetNext(false)); 
                assert(conn_wrap->evq_.Size() == 0);
            }
        }
    } else {
        ELOG("Invalid Context.");
    }
}

class TransportTrace : public TransportTraceObserver
{
public:
    static TransportTrace& GetInstance() { return inst; }

public:
    virtual void OnTransportTrace(SeverityType eType, const char* pMsg);
    inline void SetTraceCb(trace_cb_t tcb) { trace_cb = tcb; }
    inline void Register() { Transport::GetInstance()->RegisterTraceObserver(this); }
    
private:
    static TransportTrace inst;
    trace_cb_t trace_cb;

    TransportTrace() : trace_cb(NULL) {}
};

TransportTrace TransportTrace::inst;

void TransportTrace::OnTransportTrace(SeverityType eType, const char* pMsg)
{
    if (trace_cb) {
        trace_cb(log_type[eType], pMsg);
    }
}

class TransportDB
{
public:
    int addBase(TransportBase::Ptr tbase);
    inline TransportBase::Ptr getBase(uint64_t key);
    inline int removeBase(uint64_t key);
    int addConnection(connection_wrap_t* conn);
    inline int removeConnection(uint64_t key);

    static TransportDB& GetInstance() { return inst_; }

private:
    /*
     * Shared_ptr is converted to void* on the C-side. Because of it we 
     * loose the ref-count on the ptr. So lets store it in the map
     * to preserve the ref counting and for later retrieval on the C++-side.
     */
    typedef map<uint64_t, TransportBase::Ptr > TBaseMap;
    typedef map<uint64_t, connection_wrap_t* > ConnMap;

private:
    TBaseMap bases_;
    ConnMap conns_;
    MutexLock baseLock_;
    MutexLock connLock_;
    static TransportDB inst_;

    TransportDB() {}

    inline virtual ~TransportDB()
    {
    }
};

TransportDB TransportDB::inst_;

int TransportDB::addBase(TransportBase::Ptr tbase)
{
    baseLock_.Lock();

    TransportBase *tbPtr = tbase.get();
    pair<TBaseMap::iterator, bool> it = bases_.insert(make_pair(reinterpret_cast<uint64_t>(tbPtr), tbase));
    int ret = (it.second == true ? 0 : -1); 

    baseLock_.Unlock();

    return ret;
}

TransportBase::Ptr TransportDB::getBase(uint64_t key) 
{ 
    baseLock_.Lock();
    TransportBase::Ptr tBase = bases_[key];
    baseLock_.Unlock();

    return tBase;
}

int TransportDB::removeBase(uint64_t key)
{ 
    baseLock_.Lock();
    bases_.erase(key);
    baseLock_.Unlock();
    
    return 0;
}

int TransportDB::addConnection(connection_wrap_t* conn_wrap)
{
    connLock_.Lock();

    pair<ConnMap::iterator, bool> it = conns_.insert(make_pair(reinterpret_cast<uint64_t>(conn_wrap), conn_wrap));
    int ret = (it.second == true ? 0 : -1); 

    connLock_.Unlock();

    return ret;
}
    
int TransportDB::removeConnection(uint64_t id)
{
    connLock_.Lock();
    conns_.erase(id);
    connLock_.Unlock();
    
    return 0;
}

/* End: C++*/


/* Begin: C Interface*/

void fuze_transport_init(int enable_server_mode)
{
    if (enable_server_mode) {
        Transport::GetInstance()->EnableServerMode();
    }   
}

void fuze_transport_register_trace_cb(trace_cb_t trace_cb)
{
    log_type[LEVEL_DEBUG] = SWITCH_LOG_DEBUG;
    log_type[LEVEL_MSG]   = SWITCH_LOG_INFO;
    log_type[LEVEL_WARN]  = SWITCH_LOG_WARNING;
    log_type[LEVEL_ERROR] = SWITCH_LOG_ERROR;

    TransportTrace::GetInstance().SetTraceCb(trace_cb);
    TransportTrace::GetInstance().Register();
}

void* fuze_transport_create_transport_base()
{
    conn_type[CONN_UDP] = CT_UDP;
    conn_type[CONN_TCP] = CT_TCP;
    conn_type[CONN_TCP_LISTENER] = CT_TCP_LISTENER;
    conn_type[CONN_TLS] = CT_TLS;

    TransportBase::Ptr tbase = Transport::GetInstance()->CreateBase();
    if (tbase) {
	    TransportDB::GetInstance().addBase(tbase);
        return static_cast<void*>(tbase.get());
    }

    return NULL;
}

void fuze_transport_destroy_transport_base(void *tbase)
{
    if (!tbase) {
        return;
    }

    TransportBase *tbasePtr = static_cast<TransportBase*>(tbase);
    if (tbasePtr) {
        TransportDB::GetInstance().removeBase(reinterpret_cast<uint64_t>(tbasePtr));
    } 
}

void* fuze_transport_tbase_create_connection(void *tbase, connection_type_t conn_type, int rtcp, int conference)
{
    if (!tbase) {
        return NULL;
    }

    TransportBase *tbasePtr = static_cast<TransportBase*>(tbase);
    if (tbasePtr) {
        TransportBase::Ptr spTBase = TransportDB::GetInstance().getBase(reinterpret_cast<uint64_t>(tbasePtr));
        if (spTBase) {
            Connection::Ptr conn;
            if (conference) {
                conn = spTBase->CreateConnection(rtcp ? "CRTC" : "CRTP");
            }
            else {
                conn = spTBase->CreateConnection(rtcp ? "BRTC" : "BRTP");
            }
            
            if (conn) {
                connection_wrap_t *conn_wrap = new connection_wrap_t;
                conn_wrap->conn_ = conn;
                conn_wrap->conn_type_ = conn_type;
                conn_wrap->ignore_size = 0;
                
                TransportDB::GetInstance().addConnection(conn_wrap);
                
                conn->SetAppContext(conn_wrap);
                conn->RegisterObserver(&TransportPoll::GetInstance());
                conn->SetPayloadType(Connection::AUDIO);
                conn->EnableRateReport(true);
                
                return conn_wrap;
            } 
        }
    }

    return NULL;
}

const char *fuze_transport_get_connection_name(void *conn) 
{
    if (!conn) {
        return "";
    }
 
    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;

    return conn_wrap->conn_->GetName();

}

void fuze_transport_set_connection_name(void *conn, const char *name) 
{
    if (conn) {
        connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;

        conn_wrap->conn_->SetName(name);
    }
}


void fuze_transport_close_connection(void *conn)
{
    if (!conn) {
        return;
    }

    /*Make sure that we reset the fuze_shared_ptr to connection explicitly before deleting the conn_wrap.
     * otherwise there could be race condition where transport could deliver a pkt
     * after conn_wrap is deleted*/
    
    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    conn_wrap->conn_.reset();
    TransportDB::GetInstance().removeConnection(reinterpret_cast<uint64_t>(conn_wrap));

    delete conn_wrap;
}

int fuze_transport_connection_set_local_address(void *conn, const char *ip, uint16_t port)
{
    if (!conn || !ip) {
        return -1;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    conn_wrap->conn_->SetLocalAddress(string(ip), port);

    return 0;
}

int fuze_transport_connection_set_remote_address(void *conn, const char *ip, uint16_t port)
{
    if (!conn || !ip) {
        return -1;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    if (!evutil_inet_pton(AF_INET, ip, &conn_wrap->last_from_addr_.sa.sin.sin_addr)) {
        return -1;
    }
    conn_wrap->last_from_addr_.family = AF_INET;
    conn_wrap->last_from_addr_.sa.sin.sin_port = htons(port);
   
    conn_wrap->conn_->SetRemoteAddress(string(ip), port);
 
    return 0;
}

transport_status_t fuze_transport_connection_start(void *conn)
{
    if (!conn) {
        return TR_STATUS_FALSE;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    return (conn_wrap->conn_->Start(conn_type[conn_wrap->conn_type_]) == true) ? TR_STATUS_SUCCESS : TR_STATUS_FALSE;
}

transport_status_t fuze_transport_socket_poll(void *conn, int timeout_us)
{
    if (!conn) {
        return TR_STATUS_FALSE;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    return (conn_wrap->evq_.WaitUntil(timeout_us) == true) ? TR_STATUS_SUCCESS : TR_STATUS_FALSE;
}

transport_status_t fuze_transport_get_rates(void *conn, uint16_t *local_send, uint16_t *local_recv)
{
    if (!conn) {
        return TR_STATUS_FALSE;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;

    *local_send = conn_wrap->rateKbps[RT_LOCAL_SEND];
    *local_recv = conn_wrap->rateKbps[RT_LOCAL_RECV];
    
    return TR_STATUS_SUCCESS;
}

#ifdef FREE_SWITCH
int64_t get_time_usec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t result = 1000000000LL * static_cast<int64_t>(ts.tv_sec) +
    static_cast<int64_t>(ts.tv_nsec);
    return result / 1000;
}
#endif

transport_status_t fuze_transport_socket_read(void *conn, __sockaddr_t *from, 
                                              uint8_t *buf, size_t *bytes)
{
    if (!conn || !buf) {
        *bytes = 0;
        return TR_STATUS_FALSE;
    }

    connection_wrap_t *conn_wrap = (connection_wrap_t *) conn;
    TransportEvent::Ptr event;
    Buffer::Ptr rdBuf;
    int loop_cnt = 0;
#ifdef DEBUG_TIMING
    int64_t time_all = get_time_usec();
#endif
    do {
        loop_cnt += 1;
#ifdef DEBUG_TIMING
        int64_t time = get_time_usec();
        event = conn_wrap->evq_.GetNext(false);
        int64_t diff = get_time_usec() - time;
        if (diff > 1000) {
            WLOG("Queue (" << conn_wrap->evq_.Size() << ") item took " << diff << " usec");
        }
#else
        event = conn_wrap->evq_.GetNext(false);
#endif

        if (event) {

#ifdef COPY_TO_BUFFER
            if (event->len) {
                *from = conn_wrap->last_from_addr_;
                *bytes = MIN(event->len, *bytes);
                time = get_time_usec();
                memcpy(buf, event->buffer, *bytes);
                diff = get_time_usec() - time;
                if (diff > 1000) {
                    WLOG("memcpy (" << conn_wrap->evq_.Size() << ") item took " << diff << " usec");
                }
                return TR_STATUS_SUCCESS;
            } else
#endif
            {
                string IP;
                uint16_t port;
                bool remChanged;
#ifdef DEBUG_TIMING
                time = get_time_usec();
#endif
                rdBuf = event->Data(IP, port, remChanged);

                if (rdBuf) {
                    if (remChanged == true) {
                        if (!evutil_inet_pton(AF_INET, IP.c_str(), &(from->sa.sin.sin_addr))) {
                            *bytes = 0;
                            return TR_STATUS_SOCKET_ERROR;
                        }
                        from->family = AF_INET;
                        from->sa.sin.sin_port = htons(port);
                        conn_wrap->last_from_addr_ = *from;
                    }
                    else {
                        *from = conn_wrap->last_from_addr_;
                    }
                    
                    uint32_t buf_size = rdBuf->size();
                    *bytes = MIN(buf_size, *bytes);
                    if (*bytes < buf_size) {
                        ELOG("Read Buffer size: " << *bytes <<
                             " is less than the data available: " << buf_size);
                    }
                    memcpy(buf, rdBuf->getBuf(), *bytes);
                    
                    if (*bytes > 2000) {
                        ELOG("Read Buffer size large: " << *bytes);
                    }

#ifdef DEBUG_TIMING
                    diff = get_time_usec() - time;
                    if (diff > 1000) {
                        WLOG("read (" << conn_wrap->evq_.Size() << ") item took " << diff << " usec");
                    }
#endif
                    return TR_STATUS_SUCCESS;
                }
                else if (event->EvType() == ET_DISCONNECTED) {
                    *bytes = 0;
                    return TR_STATUS_DISCONNECTED;
                }
                else if (event->EvType() == ET_FAILED) {
                    *bytes = 0;
                    return TR_STATUS_SOCKET_ERROR;
                }
                else if (event->EvType() == ET_CONNECTED) {
                    /* do nothing */
                }
                else {
#ifdef DEBUG_TIMING
                    diff = get_time_usec() - time;
                    WLOG("de-Q'ed (" << conn_wrap->evq_.Size() << ") event type " <<
                         toStr(event->EvType()) << " time " << diff << " usec");
#endif
                }
            }
        }
    } while (event && !rdBuf);
#ifdef DEBUG_TIMING
    int64_t diff = get_time_usec() - time_all;
    if (diff > 1000) {
      WLOG("Queue (" << conn_wrap->evq_.Size() << ") item took " << diff << " usec");
    }
#endif
    *bytes = 0;
    return TR_STATUS_FALSE; 
}

transport_status_t fuze_transport_socket_writeto(void *conn, __sockaddr_t *rem_addr, 
                                                 const uint8_t* buf, size_t bytes)
{
    if (!conn || !buf) {
        return TR_STATUS_FALSE;
    }

    if (!rem_addr) {
        return fuze_transport_socket_write(conn, buf, bytes);
    }

    connection_wrap_t* conn_wrap = (connection_wrap_t*)conn;

    char ip_buf[16];
    string IP = evutil_inet_ntop(AF_INET, static_cast<void *>(&rem_addr->sa.sin.sin_addr),
                                 ip_buf, sizeof(ip_buf));

    if (fuze_transport_connection_set_remote_address(conn, IP.c_str(),
                                                     ntohs(rem_addr->sa.sin.sin_port))) {
        ELOG("Can not set Remote Address. Failed to send data to " << IP <<
             ":" << ntohs(rem_addr->sa.sin.sin_port));
        return TR_STATUS_FALSE;
    }
    
    return (conn_wrap->conn_->Send(buf, bytes) ? TR_STATUS_SUCCESS : TR_STATUS_FALSE);
}

transport_status_t fuze_transport_socket_write(void *conn, const uint8_t* buf, size_t bytes)
{
    if (!conn || !buf) {
        return TR_STATUS_FALSE;
    }
    
    connection_wrap_t *conn_wrap = (connection_wrap_t*)conn;

    return (conn_wrap->conn_->Send(buf, bytes) ? TR_STATUS_SUCCESS : TR_STATUS_FALSE);
}

void fuze_transport_ignore_packets(void *conn, int size)
{
   if (!conn) {
       return;
   }

   connection_wrap_t *conn_wrap = (connection_wrap_t*)conn;

   conn_wrap->ignore_size = size;
}


int fuze_udp_port_available(uint16_t port, const char* pIP)
{
    return (IsUdpPortAvailable(port, pIP) ? 0 : -1);
}

int fuze_reserve_udp_port(uint32_t holdTimeMs, uint16_t port, const char* pIP)
{
    return (ReserveUdpPort(holdTimeMs, port, pIP) ? 0 : -1);
}

extern void fuze_release_udp_port(uint16_t port)
{
    ReleaseUdpPort(port);
}

/* End: C Interface*/
