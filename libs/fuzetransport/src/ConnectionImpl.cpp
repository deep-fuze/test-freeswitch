//
//  ConnectionImpl.cpp
//  FuzeTransport
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 Tim Na. All rights reserved.
//

#include <ConnectionImpl.h>
#include <TransportImpl.h>
#include <TransportBaseImpl.h>
#include <TcpTransceiver.h>
#include <UdpTransceiver.h>
#include <ResourceMgr.h>
#include <Server.h>
#include <Log.h>
#include <sstream>
#include <iostream>

#ifndef WIN32
#include <errno.h>
#endif

#ifdef __linux__
#include <cstring> // memset
#include <cmath>
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Con[b" << baseID_ << ":c" << ID() << ":" << name_ << "] " << __FUZE_FUNC__ << ": " << B)

namespace fuze {

NoTransceiver NoTransceiver::sInstance_;

StatData::StatData(const char* pUnit)
    : pUnit_(pUnit)
{
    Clear();
}

void StatData::Clear()
{
    memset(data_, 0, sizeof(uint16_t)*MAX_NUM);
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
             << " [StdDev: " << stddev << ", data("
             << index_ << ")";
        
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
    
int Stat::AddBytes(uint32_t bytes)
{
    ++count_;
    bytes_      += bytes;
    bytes2_     += bytes;
    totalBytes_ += bytes;
    
    int64_t curr_time = GetTimeMs();
    int64_t diff = curr_time - lastTime_;

    // skip the first time
    if (lastTime_ == 0) {
        lastTime_ = curr_time;
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
                log << " (" << bytes2_ << " bytes)";
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
        lastTime_ = curr_time;
        
        return rate;
    }
    
    return -1;
}

void Connection::GenerateIceCredentials(string& ufrag, string& pwd)
{
//    ufrag = "1dNnhPLEV5ntNLe7";
//    pwd = "FuP+sXMk7A23GqBDEVDdKqFp";
//    return;

    static const char iceChar[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "+"
        "/";

    // http://c-faq.com/lib/randrange.html
    static int divisor = RAND_MAX / (sizeof(iceChar) - 1) + 1;
    
    char ufragBuf[ICE_UFRAG_LEN];
    char pwdBuf[ICE_PWD_LEN];

    for (size_t i = 0; i < ICE_UFRAG_LEN-1; ++i) {
        ufragBuf[i] = iceChar[rand()/divisor];
    }
    ufragBuf[ICE_UFRAG_LEN-1] = 0;
    ufrag = ufragBuf;

    for (size_t i = 0; i < ICE_PWD_LEN-1; ++i) {
        pwdBuf[i] = iceChar[rand()/divisor];
    }
    pwdBuf[ICE_PWD_LEN-1] = 0;
    pwd = pwdBuf;
}
    
ConnectionImpl::ConnectionImpl(int connID)
    : Resource(connID)
    , baseID_(-1)
    , pAppContext_(0)
    , bFallback_(false)
    , origType_(CT_INVALID)
    , pTransceiver_(NoTransceiver::GetInstance())
    , state_(0)
    , pObserver_(0)
    , removeBinding_(false)
    , bWYSWYG_(false)
    , bRateReport_(false)
    , payloadType_(0)
    , sendStat_(this)
    , timeStat_("ms")
    , delayStat_("ms")
    , lastDelayStat_(0)
    , bRemotePerBuf_(false)
    , workerId_(0)
	, bReservePort_(false)
    , bufNum_(0)
{
    SetName("");
    
    for (int i = 0; i < MAX_QUEUE_SIZE; ++i) {
        recycleQ_.push_back(BufferQueue());
    }
    
    memset(bufAlloc, 0, sizeof(bufAlloc));
}

ConnectionImpl::~ConnectionImpl()
{
}

void ConnectionImpl::SetBaseID(int baseID)
{
    baseID_ = baseID;
}
    
int ConnectionImpl::BaseID()
{
    return baseID_;
}

bool ConnectionImpl::Start(ConnectionType eType, int mode)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    // assign worker thread
    spWorker_ = TransportImpl::GetInstance()->GetWorker(this);
    workerId_ = spWorker_->ID();
    
    MLOG("Assigned with thread [" << spWorker_->Name() << "]");
    
    // validate eType
    switch (eType)
    {
    case CT_UDP:
    case CT_DTLS_CLIENT:
    case CT_DTLS_SERVER:
    case CT_TCP:
    case CT_TCP_LISTENER:
    case CT_TLS:
        break;
    default:
        ELOG("ConnectionType " << toStr(eType) << " is not allowed");
        return false;
    }
    
    MLOG("Requested connection type: " << toStr(eType));
    
    // remember the original type so that we correctly set
    // firewall traversal state machine per type
    origType_ = eType;
    
    // set default behavior for TCP if used
    TcpTxrxState::Type state_type = TcpTxrxState::SETUP_TCP;
    if (eType == CT_TLS) {
        state_type = TcpTxrxState::SETUP_TLS;
    }
    
    // if app is client then check network status and type
    if (TransportImpl::GetInstance()->IsAppServer() == false) {

        string proxy, credential;
        proxy::Type proxy_type;
        proxy::GetInfo(proxy, credential, proxy_type);
        
        // check if we have proxy setup and remote is not
        // IP address due to blocked DNS in some corporate environment
        if (!proxy.empty()
#ifndef FORCE_HTTP_PROXY
            && !remote_.Valid() && !domainRemote_.empty()
#else // specify which connection to use HTTP Proxy using debug name
            && strncmp(name_, "SIP-TLS", 7) == 0
#endif
            ) {
            MLOG("Forcing HTTP proxy traversal with " <<
                 domainRemote_ << " using proxy " << proxy);
            eType       = CT_TCP;
            origRemote_ = remote_;
            get_http_proxy_address(remote_);
            remote_.SetPort(Server::PORT);
            state_type = TcpTxrxState::SETUP_HTTP_TLS;
            OnEvent(ET_IN_PROGRESS, toStr(state_type));
        }
        else { // check to see if we are forcing TLS
            bool bForceTls = ((mode & FORCE_FUZE_TLS) != 0);
            if (bForceTls) {
                MLOG("App requested to force FuzeTLS on " << toStr(eType));
                eType         = CT_TCP;
                origRemote_   = remote_;
                remote_.SetPort(Server::PORT);
                state_type    = TcpTxrxState::SETUP_TLS;
                // no firewall but TLS is forced
                OnEvent(ET_IN_PROGRESS, toStr(state_type));
            }
        }
        
        bFallback_ = ((mode & NO_FALLBACK) == 0);
        
        // For DTLS, disable fallback for now
        if (eType & CT_DTLS_TYPE) {
            bFallback_ = false;
        }
    }
    
    MLOG("Final type: " << toStr(eType) << " (fallback " <<
         (bFallback_ ? "en" : "dis") << "abled" <<
         ((mode & FORCE_FUZE_TLS) ? ", ForceFuzeTLS" : "") << ")");
    
    bool bResult = false;
    
    pTransceiver_ = ResourceMgr::GetInstance()->GetNewTransceiver(eType);
    if (pTransceiver_) {
        pTransceiver_->SetConnectionID(ID());
        
        // if this is TcpTransceiver then set TcpTxrxState
        if (eType & CT_STREAM_TYPE) {
            if (TcpTransceiver* p =
                    dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                if (state_type != TcpTxrxState::SETUP_TCP) {
                    p->SetState(state_type, true);
                }
                if (bWYSWYG_) {
                    p->EnableTcpFramer();
                }
            }
        }
        
        sprintf(sendStat_.log_, "Con[b%d:c%d:%s] Tx rate: ", baseID_, ID(), name_);
        sprintf(recvStat_.log_, "Con[b%d:c%d:%s] Rx rate: ", baseID_, ID(), name_);

        MLOG("Starting " << toStr(pTransceiver_->ConnType()));
        
        // check if we are starting HTTP proxy traversal
        if ((state_type != TcpTxrxState::SETUP_HTTP) &&
            (state_type != TcpTxrxState::SETUP_HTTP_TLS)) {
            bResult = pTransceiver_->Start();
        }
        else if (TcpTransceiver* p =
                 dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
            p->PrepareProxyConnect();
            bResult = true;
        }
        
        if (bResult && TransportImpl::GetInstance()->IsAppServer()) {
            // register this connection to firewall traversal server
            // if this is UDP server or TCP listener
            if ((eType == CT_UDP && local_.Valid()) ||
                eType == CT_TCP_LISTENER) {
                if (Server::Ptr sp_server =
                    TransportImpl::GetInstance()->GetServer()) {
                    sp_server->SetConnectionBinding(ID());
                    removeBinding_ = true;
                }
            }
        }
    }
    
    return bResult;
}

void ConnectionImpl::Reset()
{
    if (IsActive() == true) {
        DLOG("ACTIVE -> ZOMBIE");
        
        // Remove the binding first if we need to as it
        // requires to access valid types of data below
        if (removeBinding_) {
            if (Server::Ptr sp_server =
                TransportImpl::GetInstance()->GetServer()) {
                sp_server->RemoveConnectionBinding(ID());
            }
        }
        
        SetZombie();
        
        if (spWorker_) {
            spWorker_.reset();
            workerId_ = 0;
            queue<Buffer::Ptr> empty_q;
            queue<EventData>   empty_e;
            queue<RateData>    empty_r;
            MutexLock scoped(&qLock_);
            swap(workQ_, empty_q);
            swap(eventQ_, empty_e);
            swap(rateQ_, empty_r);
        }
        
        MLOG("SendStat: " << sendStat_.totalBytes_ <<
             " bytes sent, count(" << sendStat_.count_ << ")");
        sendStat_.Clear();
        
        MLOG("RecvStat: " << recvStat_.totalBytes_ <<
             " bytes received, count(" << recvStat_.count_ << ")");
        recvStat_.Clear();
        
        // release all the buffer used
        int buf_free[MAX_QUEUE_SIZE];
        
        {
            memset(buf_free, 0, sizeof(buf_free));
            
            MutexLock scoped(&rcqLock_);
            for (int i = 0; i < MAX_QUEUE_SIZE; ++i) {
                while (!recycleQ_[i].empty()) {
                    buf_free[i]++;
                    delete recycleQ_[i].front();
                    recycleQ_[i].pop();
                }
            }
        }
        
        bufNum_ = 0;
        
        MLOG("MemoryStat: " <<
             "shallow (" << buf_free[SHALLOW_COPY] << "/" << bufAlloc[SHALLOW_COPY] <<
             ") 64 (" << buf_free[SIZE_64] << "/" << bufAlloc[SIZE_64] <<
             ") 256 (" << buf_free[SIZE_256] << "/" << bufAlloc[SIZE_256] <<
             ") 1024 (" << buf_free[SIZE_1024] << "/" << bufAlloc[SIZE_1024] <<
             ") 2048 (" << buf_free[SIZE_2048] << "/" << bufAlloc[SIZE_2048] <<
             ") 32000 (" << buf_free[SIZE_32000] << "/" << bufAlloc[SIZE_32000] <<
             ") 65000 (" << buf_free[SIZE_65000] << "/" << bufAlloc[SIZE_65000] <<
             ") 262000 (" << buf_free[SIZE_262000] << "/" << bufAlloc[SIZE_262000] <<
             ")");
        
        memset(bufAlloc, 0, sizeof(bufAlloc));
        
        timeStat_.Clear();
        delayStat_.Clear();
        lastDelayStat_  = 0;
        
        removeBinding_  = false;
        baseID_         = -1;
        pAppContext_    = 0;
        state_          = 0;
        
        name_[0] = 0;
        local_.Clear();
        remote_.Clear();
        origRemote_.Clear();
        b4akamaiMap_.Clear();
        domainRemote_.clear();
        wpObserver_.reset();

        pObserver_     = 0;
        bWYSWYG_       = false;
        bRateReport_   = false;
        payloadType_   = 0;
        bRemotePerBuf_ = false;
        bReservePort_  = false;

        ReplaceTransceiver(NoTransceiver::GetInstance());
    }
}
    
void ConnectionImpl::RegisterObserver(ConnectionObserver* pObserver)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    MutexLock scoped(&conLock_);    
    pObserver_ = pObserver;
}

void ConnectionImpl::RegisterObserver(ConnectionObserver::WPtr wPtr)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    wpObserver_ = wPtr;
}
    
void ConnectionImpl::DeregisterObserver()
{
    if (pObserver_) {
        MLOG("start");
        {
            MutexLock scoped(&conLock_);
            pObserver_ = 0;
        }
        MLOG("end");
    }
}
    
void ConnectionImpl::SetName(const char* pName)
{
    memset(name_, 0, 16); // init name
    if (pName && *pName) {
        for (int i = 0; i < 15; ++i) {
            if (pName[i]) {
                name_[i] = pName[i];
            }
            else {
                break;
            }
        }
        
        snprintf(sendStat_.log_, 64, "Con[b%d:c%d:%s] Tx rate: ",
                baseID_, ID(), name_);
        snprintf(recvStat_.log_, 64, "Con[b%d:c%d:%s] Rx rate: ",
                baseID_, ID(), name_);
    }
}
    
const char* ConnectionImpl::GetName()
{
    return name_;
}
    
bool ConnectionImpl::SetAppContext(void* pContext)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    MLOG("App context set to " << pContext);
    
    pAppContext_ = pContext;
    
    return true;
}

bool ConnectionImpl::SetLocalAddress(const string& IP, uint16_t port)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    bool result = false;
    
    MLOG(local_ << " -> " << IP << ":" << port);
    
    if (local_.SetIP(IP.c_str()) && local_.SetPort(port)) {
        result = true;
    }
    else {
        ELOG("Invalid IP address: " << IP);
    }
    
    return result;
}
    
bool ConnectionImpl::SetRemoteAddress(const string& IP, uint16_t port)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    // application may have used domain name instead
    string remote_addr = IP;
    
    MLOG(remote_ << " -> " << remote_addr << ":" << port);
    
    remote_.SetPort(port);
    
    // check if remote is set as domain not IP
    if (remote_.SetIP(remote_addr.c_str()) == false) {

        // check if HTTP proxy is configured as some company won't even
        // allow DNS lookup in this network setting
        string mapped_ip = TranslateToIP(remote_addr.c_str());
        
        if (mapped_ip.empty()) {
            // this is case where some corporate won't allow DNS at all
            domainRemote_ = remote_addr;
        }
        else {
            MLOG("Remote " << IP << " translated to " << mapped_ip);
            remote_.SetIP(mapped_ip.c_str());
            remote_addr = mapped_ip;
        }
    }
    
    // if client, check if remote IP has Akamai mapping
    if (TransportImpl::GetInstance()->IsAppServer() == false) {
        string mapped = TransportImpl::GetInstance()->GetAkamaiMapping(remote_addr);
        if (!mapped.empty()) {
            MLOG("Akamai mapping found for " << remote_addr << " as " << mapped);
            string akamai_ip = TranslateToIP(mapped);
            if (!akamai_ip.empty()) {
                b4akamaiMap_ = remote_; // remember their mapping in case of their bug
                remote_.SetIP(akamai_ip.c_str());
            }
        }
    }
    
    return true;
}

void ConnectionImpl::SetWYSWYGMode()
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    bWYSWYG_ = true;
    
    if (pTransceiver_->ConnType() == CT_TCP) {
        if (TcpTransceiver* p_tcp =
                dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
            p_tcp->EnableTcpFramer();
        }
    }
}

void ConnectionImpl::SetLocalIceCredential(const string& rUser, const string& rPwd)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    MutexLock scoped(&lock_);
    localUser_     = rUser;
    localPassword_ = rPwd;
}
    
void ConnectionImpl::SetRemoteIceCredential(const string& rUser, const string& rPwd)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    MutexLock scoped(&lock_);
    remoteUser_     = rUser;
    remotePassword_ = rPwd;
}
    
void ConnectionImpl::SetPayloadType(uint32_t flag)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    if (flag & Connection::STUN)  MLOG("Setting payload as STUN");
    if (flag & Connection::RTP)   MLOG("Setting payload as RTP");
    if (flag & Connection::RTCP)  MLOG("Setting payload as RTCP");
    if (flag & Connection::SIP)   MLOG("Setting payload as SIP");
    if (flag & Connection::AUDIO) MLOG("Setting payload as AUDIO");
    if (flag & Connection::VIDEO) MLOG("Setting payload as VIDEO");
    if (flag & Connection::SS)    MLOG("Setting payload as SS");
    
    payloadType_ |= flag;
}

bool ConnectionImpl::IsFallback()
{
    return bFallback_;
}
    
void ConnectionImpl::GetLocalIceCredential(string& rUser, string& rPwd)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    MutexLock scoped(&lock_);
    rUser = localUser_;
    rPwd  = localPassword_;
}

void ConnectionImpl::SetRemoteAddressPerBuffer(bool enabled)
{
    bRemotePerBuf_ = enabled;
}

void ConnectionImpl::GetRemoteIceCredential(string& rUser, string& rPwd)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    MutexLock scoped(&lock_);
    rUser = remoteUser_;
    rPwd  = remotePassword_;
}
    
bool ConnectionImpl::Send(Buffer::Ptr spBuffer)
{
    if (IsActive() == false) {
        int64_t curr = GetTimeMs();
        if (curr - sendStat_.lastTime_ > 2000) {
            ELOG(GetStatusString());
            sendStat_.lastTime_ = curr;
        }
        return false;
    }

    MutexLock scoped(&transLock_);
    
    return pTransceiver_->Send(spBuffer);
}

bool ConnectionImpl::Send(const unsigned char* buf, size_t size)
{
    if (IsActive() == false) {
        int64_t curr = GetTimeMs();
        if (curr - sendStat_.lastTime_ > 2000) {
            ELOG(GetStatusString());
            sendStat_.lastTime_ = curr;
        }
        return false;
    }

    MutexLock scoped(&transLock_);

    return pTransceiver_->Send(buf, size);
}
    
bool ConnectionImpl::GetConnectedType(ConnectionType& rType)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
  
    rType = pTransceiver_->ConnType();
    
    return true;
}

bool ConnectionImpl::GetLocalAddress(string& rIP, uint16_t& rPort)
{
    bool bResult = false;
    
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    if (local_.Valid()) {
        rIP     = local_.IPString();
        rPort   = local_.Port();
        bResult = true;
    }
    
    return bResult;
}

bool ConnectionImpl::GetRemoteAddress(string& rIP, uint16_t& rPort)
{
    bool bResult = false;
    
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    if (remote_.Valid()) {
        rIP     = remote_.IPString();
        rPort   = remote_.Port();
        bResult = true;
    }
    else if (!domainRemote_.empty()) {
        rIP     = domainRemote_;
        rPort   = remote_.Port();
        bResult = true;
    }
    
    return bResult;
}

void ConnectionImpl::GetSendQInfo(size_t& rNum, uint32_t& rBufSize)
{
    MutexLock scoped(&transLock_);
    
    ConnectionType type = pTransceiver_->ConnType();
    
    if (type == CT_TCP || type == CT_TLS) {
        if (TcpTransceiver* p =
                dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
            p->GetSendQInfo(rNum, rBufSize);
        }
    }
    else {
        rNum = 0;
        rBufSize = 0;
    }
}

void ConnectionImpl::EnableRateReport(bool flag)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return;
    }
    
    bRateReport_ = flag;
}
    
uint32_t ConnectionImpl::GetSendRetryCount()
{
    uint32_t retry = 0;
    
    MutexLock scoped(&transLock_);
    
    ConnectionType type = pTransceiver_->ConnType();
    
    if (type == CT_TCP || type == CT_TLS) {
        if (TcpTransceiver* p =
            dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
            retry = p->GetSendRetryCount();
        }
    }
    
    return retry;
}
    
const Address& ConnectionImpl::GetLocalAddress()
{
    return local_;
}

const Address& ConnectionImpl::GetRemoteAddress()
{
    return remote_;
}
    
bool ConnectionImpl::Initialize(ConnectionType  eType,
                                evutil_socket_t sock,
                                bool            overTLS)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    // assign worker thread
    spWorker_ = TransportImpl::GetInstance()->GetWorker(this);
    workerId_ = spWorker_->ID();
    
    MLOG("Assigned with thread [" << spWorker_->Name() << "]");
    
    sprintf(sendStat_.log_, "Con[b%d:c%d] Tx rate: ", baseID_, ID());
    sprintf(recvStat_.log_, "Con[b%d:c%d] Rx rate: ", baseID_, ID());
    
    bool bResult = false;
    
    pTransceiver_ = ResourceMgr::GetInstance()->GetNewTransceiver(eType);
    if (pTransceiver_) {
        pTransceiver_->SetConnectionID(ID());
        
        if (eType == CT_TCP) {
            if (TcpTransceiver* p =
                    dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                // flag to set different TcpTxrxState
                if (overTLS) {
                    p->SetState(TcpTxrxState::DATA_OVER_TLS);
                }
                else {
                    p->SetState(TcpTxrxState::TCP);
                }
                
                bResult = p->Start(sock);
            }
        }
    }
    
    return bResult;
}

bool ConnectionImpl::ServiceQueue(ThreadID_t workerID)
{
    if (workerId_ != workerID) {
        return false;
    }
    
    if (!workQ_.empty()) {
        Buffer::Ptr sp_buf;
        {
            MutexLock scoped(&qLock_);
            if (!workQ_.empty()) {
                sp_buf = workQ_.front();
                workQ_.pop();
            }
        }
        if (sp_buf) {
            DeliverData(sp_buf);
        }
    }
    
    if (!eventQ_.empty()) {
        bool report_event = false;
        EventData event_data;
        {
            MutexLock scoped(&qLock_);
            if (!eventQ_.empty()) {
                event_data = eventQ_.front();
                eventQ_.pop();
                report_event = true;
            }
        }
        if (report_event) {
            DeliverEventData(event_data);
        }
    }
    
    if (!rateQ_.empty()) {
        bool report_rate = false;
        RateData rate_data;
        {
            MutexLock scoped(&qLock_);
            if (!rateQ_.empty()) {
                rate_data = rateQ_.front();
                rateQ_.pop();
                report_rate = true;
            }
        }
        if (report_rate) {
            DeliverRateData(rate_data);
        }
    }
    
    return true;
}
    
void ConnectionImpl::OnData(Buffer::Ptr spBuffer)
{
    if (!IsActive() || !spWorker_)  return;
    
    {
        MutexLock scoped(&qLock_);
        size_t q_size = workQ_.size();
        if (q_size && (q_size % 1000) == 0) {
            WLOG("WorkQ reached " << q_size);
        }
        
        workQ_.push(spBuffer);
    }
    
    spWorker_->SetWork(this);
}
    
void ConnectionImpl::DeliverData(Buffer::Ptr spBuffer)
{
    DLOG("Sending data to App: " << spBuffer->size() << " bytes");
    
	uint64_t start_time = GetTimeMs();
    
    try {
        if (wpObserver_.expired()) {
            MutexLock scoped(&conLock_);
            if (pObserver_) {
                pObserver_->OnDataReceived(pAppContext_, spBuffer);
            }
        }
        else {
            if (ConnectionObserver::Ptr sp = wpObserver_.lock()) {
                sp->OnDataReceived(pAppContext_, spBuffer);
            }
        }
    }
    catch (std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
    
	int64_t diff = GetTimeMs() - start_time;
	if (diff > 5) {
        timeStat_.SetData((uint16_t)diff);
        
        if (lastDelayStat_ == 0) {
            lastDelayStat_ = start_time;
        }
        
        uint16_t time_gap = uint16_t(start_time - lastDelayStat_);
        lastDelayStat_ = start_time;
        delayStat_.SetData(time_gap);
        
        // every 20 events print it
        if ((timeStat_.seq_ % 20) == 0) {
            ostringstream log;
            timeStat_.Display(log, "",  "Time Delayed ");
            delayStat_.Display(log, "", "Delay Gap    ");
            WLOG("App delayed transport thread" << log.str());
            
            OnEvent(ET_APP_DELAY, "App delaying transport thread");
        }
	}
}
    
void ConnectionImpl::OnEvent(EventType eType, const char* pReason)
{
    MLOG(toStr(eType) << " (" << pReason << ")");
    
    // hack to avoid retry when mapping failed -
    // need more elegant solution
    bool map_failed = (strcmp(pReason, "Failed to map connection") == 0);

    // We should be doing failover only in these cases
    //
    // 1. UDP - Failover happens in OnTransceiverTimeout
    //          or recv returned error
    // 2. All failures with TCP setup phase
    if (is_end_event(eType) && !map_failed &&
        TransportImpl::GetInstance()->IsAppServer() == false) {
    
        // if we are connected and got this error and check if network changed
        if (InState(CONNECTED)) {
            WLOG("Network ended during connected state - check network change");
            if (RetryIfNetworkChanged()) {
                return;
            }
        }
        
        ConnectionType conn_type = pTransceiver_->ConnType();
        
        if (conn_type == CT_UDP) {
            // Usually UDP won't fail unless it is connected-udp
            // however, os firewall or anti-virus may still do
            // the un-thinkable thing.
            if (InState(CONNECTED) == false) {
                WLOG("UDP returned failure - try failover now");
                if (Failover()) {
                    return; // failing over now
                }
            }
        }
        else if (conn_type == CT_TCP) {
            if (TcpTransceiver* p = dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                // check whether we were doing setup or not
                if (is_setup_state(p->GetStateType())) {
                    // check what setup state we started with.
                    // this is because pState_ changes over time
                    switch (p->GetSetupMethodType())
                    {
                    case TcpTxrxState::SETUP_TCP:
                    case TcpTxrxState::SETUP_TCP_443:
                    case TcpTxrxState::SETUP_TLS:
                    case TcpTxrxState::SETUP_HTTP:
                        if (Failover()) {
                            return; // we are doing failover now
                        }
                        else {
                            ELOG("Failed to perform failover on " <<
                                 toStr(p->GetSetupMethodType()));
                            eType = ET_FAILED;
                        }
                        break;
                    case TcpTxrxState::SETUP_HTTP_TLS:
                        MLOG("no more option to connect far end");
                        eType = ET_FAILED;
                        break;
                    default:
                        ELOG("Unexpected type: " <<
                             toStr(p->GetSetupMethodType()));
                    }
                }
            }
        }
    }

    if (eType == ET_CONNECTED) {
        SetState(CONNECTED); // mark that we are conneceted now
    }
    
    // for app server, set transceiver to NoTransceiver pointer
    // to prevent sending from application as socket layer is
    // useless to use anymore.  However, we are keeping this
    // connection instance until application specifically ends it
    // as client can always reconnect using FuzeTLS
    //
    // It's important to do this in context of transport thread as
    // send/recv work is done with transport thread.  Worker thread
    // shouldn't be doing this as it can interfere and crash with
    // transport thread's work
    //
    if (is_end_event(eType) && TransportImpl::GetInstance()->IsAppServer()) {
        ReplaceTransceiver(NoTransceiver::GetInstance());
    }
    
    EventData event_data;
    event_data.type_ = eType;
    event_data.reason_ = pReason;

    {
        MutexLock scoped(&qLock_);
        eventQ_.push(event_data);
    }
    
    spWorker_->SetWork(this);
}

void ConnectionImpl::DeliverEventData(EventData &rEvent)
{
    // bubble at most once of failed event
    if (is_end_event(rEvent.type_)) {
        if (InState(TERMINATED)) {
            WLOG("Connection in terminated state - event ignored");
            return;
        }
        else {
            SetState(TERMINATED);
        }
    }
    
    uint64_t start_time = GetTimeMs();
    
    try {
        if (wpObserver_.expired()) {
            MutexLock scoped(&conLock_);
            if (pObserver_) {
                pObserver_->OnEvent(pAppContext_, rEvent.type_, rEvent.reason_);
            }
        }
        else {
            if (ConnectionObserver::Ptr sp = wpObserver_.lock()) {
                sp->OnEvent(pAppContext_, rEvent.type_, rEvent.reason_);
            }
        }
    }
    catch (std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
    
    int64_t diff = GetTimeMs() - start_time;
    if (diff > 5) {
        WLOG("App delayed libevent thread " << diff << " ms");
    }
    
    // when end event is detected then reset the connection
    if (is_end_event(rEvent.type_)) {
        TransportImpl* p = TransportImpl::GetInstance();
        if (p->IsAppServer() == false) {
            p->RequestReset(Resource::CONNECTION, ID());
        }
    }
}
    
void ConnectionImpl::OnRateData(RateType type, uint16_t rate, uint16_t delta)
{
    RateData rate_data;
    rate_data.type_  = type;
    rate_data.rate_  = rate;
    rate_data.delta_ = delta;
    
    {
        MutexLock scoped(&qLock_);
        rateQ_.push(rate_data);
    }
    
    spWorker_->SetWork(this);
}

void ConnectionImpl::DeliverRateData(fuze::ConnectionImpl::RateData &rRate)
{
    try {
        if (wpObserver_.expired()) {
            MutexLock scoped(&conLock_);
            if (pObserver_) {
                pObserver_->OnRateData(rRate.type_, rRate.rate_, rRate.delta_);
            }
        }
        else {
            if (ConnectionObserver::Ptr sp = wpObserver_.lock()) {
                sp->OnRateData(rRate.type_, rRate.rate_, rRate.delta_);
            }
        }
    }
    catch (std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
}
    
uint32_t ConnectionImpl::OnBytesSent(uint32_t bytesSent)
{
    int rate = sendStat_.AddBytes(bytesSent);
    
    if (rate != -1) {
        uint16_t send_rate = (uint16_t)rate;
        
        if (bWYSWYG_) {
            if (TcpTransceiver* p =
                dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                p->SendStat(Stat::TYPE_SEND,send_rate,
                            sendStat_.local_.seq_);
            }
        }
        
        if (bRateReport_) {
            int64_t curr_time = GetTimeMs();
            if (!sendStat_.lastSent_) {
                sendStat_.lastSent_ = curr_time;
            }
            uint16_t diff = uint16_t(curr_time - sendStat_.lastSent_);
            OnRateData(RT_LOCAL_SEND, send_rate, diff);
            sendStat_.lastSent_ = curr_time;
        }
    }

    if (sendStat_.count_ <= 5) {
        MLOG(bytesSent << "B (count: " << sendStat_.count_ << ")");
    }
    
    return sendStat_.count_;
}

uint32_t ConnectionImpl::OnBytesRecv(uint32_t bytesRecv)
{
    int rate = recvStat_.AddBytes(bytesRecv);
    
    if (rate != -1) {
        uint16_t recv_rate = (uint16_t)rate;
        
        if (bWYSWYG_) {
            if (TcpTransceiver* p =
                dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                p->SendStat(Stat::TYPE_RECV, recv_rate,
                            recvStat_.local_.seq_);
            }
        }
        
        if (bRateReport_) {
            int64_t curr_time = GetTimeMs();
            if (!recvStat_.lastSent_) {
                recvStat_.lastSent_ = curr_time;
            }
            uint16_t diff = uint16_t(curr_time - recvStat_.lastSent_);
            OnRateData(RT_LOCAL_RECV, recv_rate, diff);
            recvStat_.lastSent_ = curr_time;
        }
    }
    
    if (recvStat_.count_ == 1) {
        if (pTransceiver_->ConnType() == CT_UDP) {
            OnEvent(ET_CONNECTED, "received first packet");
        }
    }
    
    if (recvStat_.count_ <= 5) {
        MLOG(bytesRecv << "B (count: " << recvStat_.count_ << ")");
    }
    
    return recvStat_.count_;
}

void ConnectionImpl::ClearStat()
{
    // Once we are connected, clear data stat used
    // to be connected to reflect application data only
    //
    MLOG("SendStat: " << sendStat_.totalBytes_ <<
         " bytes sent, count(" << sendStat_.count_ << ")");
    sendStat_.Clear();
    
    MLOG("RecvStat: " << recvStat_.totalBytes_ <<
         " bytes received, count(" << recvStat_.count_ << ")");
    recvStat_.Clear();
}
    
void ConnectionImpl::OnStatReceived(Buffer::Ptr spStat)
{
    if (spStat->size() < 7) {
        ELOG("lack of size: " << spStat->size());
        return;
    }

    uint8_t* p_stat = spStat->getBuf();
    uint8_t  type = *p_stat;
    p_stat++;
    uint16_t rate;
    memcpy(&rate, p_stat, sizeof(uint16_t));
    rate = ntohs(rate);
    p_stat += sizeof(uint16_t);
    uint32_t seq;
    memcpy(&seq, p_stat, sizeof(uint32_t));
    seq = ntohl(seq);

    Stat& r_stat = (type == Stat::TYPE_SEND ? recvStat_ : sendStat_);
    
    StatData& r_data = r_stat.remote_;
    r_data.SetData(rate);
    if (r_data.seq_ != seq) {
        WLOG("Stat Sequence mismatch - expected " <<
             r_data.seq_ << ", received: " << seq);
        r_data.seq_ = seq;
    }
    
    // measure the time of jitter
    int64_t curr_time = GetTimeMs();
    uint16_t diff = 0;
    if (r_stat.lastArrival_ != 0) {
        diff = uint16_t(curr_time - r_stat.lastArrival_);
    }
    r_stat.arrival_.SetData(diff);
    r_stat.lastArrival_ = curr_time;
    
    if (bRateReport_) {
        if (type == Stat::TYPE_SEND) {
            OnRateData(RT_REMOTE_SEND, rate, diff);
        }
        else {
            OnRateData(RT_REMOTE_RECV, rate, diff);
        }
    }
}

void ConnectionImpl::OnMapReceived(Buffer::Ptr spMap)
{
    if (spMap->size() < 10) {
        ELOG("lack of size: " << spMap->size());
        return;
    }
    
    uint8_t* p_map = spMap->getBuf();
    
    in_addr  mapped_ip;
    uint16_t mapped_port = 0;
    uint32_t rand_num    = 0;

    memcpy(&mapped_ip, p_map, sizeof(uint32_t));
    p_map += sizeof(uint32_t);
    
    memcpy(&mapped_port, p_map, sizeof(uint16_t));
    mapped_port = ntohs(mapped_port);
    p_map += sizeof(uint16_t);
    
    memcpy(&rand_num, p_map, sizeof(uint32_t));
    rand_num = ntohl(rand_num);
    
    MLOG(toStr(mapped_ip) << ":" << mapped_port << " key: " << rand_num);
}
    
void ConnectionImpl::OnTransceiverTimeout()
{
    //
    // this method is called for client to use not server application
    //
    if (TransportImpl::GetInstance()->IsAppServer()) {
        ELOG("Received timeout for server connection");
        return;
    }
    
    MLOG("recv packet # " << recvStat_.count_ <<
         (bFallback_ ? "" : " - ignored as fallback disabled"));
    
    if (!bFallback_) {
        return;
    }
    
    if (InState(CONNECTED) == false) {
        if (Failover() == false) {
            OnEvent(ET_FAILED, "Network failure");
        }
    }
    else {
        if (RetryIfNetworkChanged() == false) {
            // filter this event for other service like screen sharing and vidyo
            if (origType_ == CT_UDP) {
                // try the same transport type again if not udp
                bool is_udp = (pTransceiver_->ConnType() == CT_UDP);
                bool retry_same_type = (is_udp ? false : true);
                if (Failover(retry_same_type)) {
                    if (is_udp) {
                        ClearStat();
                    }
                }
                else {
                    OnEvent(ET_FAILED, "Failure during active session");
                }
            }
        }
    }
}

bool ConnectionImpl::Failover(bool bRetrySameType)
{
    // if we haven't received any packets yet and fallback is enabled
    if (!bFallback_) {
        ELOG("Fallback is not enabled");
        return false;
    }

    MLOG("RetrySameType: " << (bRetrySameType ? "true" : "false"));
    
    bool bResult = false;

    ConnectionType     type = pTransceiver_->ConnType();
    TcpTxrxState::Type state_type = TcpTxrxState::SETUP_TLS;
    string             event_str(toStr(type));
    
    if (bRetrySameType) {
        if ((type == CT_TCP) || (type == CT_TLS)) {
            if (TcpTransceiver* p
                    = dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                state_type = p->GetSetupMethodType();
                event_str  = toStr(state_type);
            }
        }
    }
    else {
        // record original remote address if we didn't remember it before
        if (origRemote_.Valid() == false) {
            origRemote_ = remote_;
        }
        
        if (type == CT_UDP) {
            type = CT_TCP;
            state_type = TcpTxrxState::SETUP_TLS;
            remote_.SetPort(Server::PORT);
            MLOG("transition UDP -> TLS [" << toStr(state_type) << "]");
        }
        else if ((type == CT_TCP) || (type == CT_TLS)) {
            TcpTransceiver* p = dynamic_cast<TcpTransceiver*>(pTransceiver_);
            if (!p) {
                ELOG("No TcpTransceiver");
                return false;
            }
            
            TcpTxrxState::Type curr_state = p->GetSetupMethodType();
            
            switch (curr_state)
            {
            case TcpTxrxState::SETUP_TCP:
                remote_.SetPort(Server::PORT);
                // skip TCP 443 for cases where firewall blocking us
                state_type = TcpTxrxState::SETUP_TLS;
                break;
            case TcpTxrxState::SETUP_TCP_443:
                state_type = TcpTxrxState::SETUP_TLS;
                break;
            case TcpTxrxState::SETUP_TLS:
            case TcpTxrxState::SETUP_MAP_TLS:
            {
                // if we are failed during process HTTP TLS
                // SETUP_HTTP_TLS -> SETUP_TLS -> SETUP_MAP_TLS
                // we shouldn't be going into SETUP_HTTP_TLS again
                // check current remote_ to see to check this
                Address proxy_addr;
                if (get_http_proxy_address(proxy_addr)) {
                    if (proxy_addr != remote_) {
                        // skip TCP 443 for cases where firewall blocking us
                        state_type = TcpTxrxState::SETUP_HTTP_TLS;
                        remote_ = proxy_addr;
                    }
                    else {
                        WLOG("Failed to go thru HTTP proxy " << remote_);
                        return false;
                    }
                }
                else {
                    WLOG("Proxy is not available to go thru");
                    return false;
                }
                break;
            }
            case TcpTxrxState::SETUP_HTTP:
                state_type = TcpTxrxState::SETUP_HTTP_TLS;
                break;
            case TcpTxrxState::SETUP_HTTP_TLS: // HTTP setup failed - no more hope
            case TcpTxrxState::UDP_OVER_TCP:   // can't failover in these final states
            case TcpTxrxState::DATA_OVER_TLS:
            case TcpTxrxState::TLS:
            case TcpTxrxState::TCP:
                MLOG("can't failover on " << toStr(curr_state));
                return false;
            }
            
            MLOG("transition " << toStr(p->GetSetupMethodType()) <<
                 " -> " << toStr(state_type));
        }
        else {
            ELOG("can't failover connection type: " << toStr(type));
            return false;
        }
        
        event_str = toStr(state_type);
    }
    
    OnEvent(ET_IN_PROGRESS, event_str.c_str());
    
    if (Transceiver* p =
            ResourceMgr::GetInstance()->GetNewTransceiver(type)) {
        
        // set tcp state to deal with connection setup
        if (TcpTransceiver* p_tcp = dynamic_cast<TcpTransceiver*>(p)) {
            
            p_tcp->SetConnectionID(ID());
            p_tcp->SetState(state_type, true); // set as setup method
            
            ReplaceTransceiver(p_tcp);
            
            if ((state_type != TcpTxrxState::SETUP_HTTP) &&
                (state_type != TcpTxrxState::SETUP_HTTP_TLS)) {
                bResult = p_tcp->Start();
            }
            else {
                p_tcp->PrepareProxyConnect();
                bResult = true;
            }
        }
        else { // UdpTransceiver only for now
            // local address is not valid anymore so clear it
            // this will force our UDP to be used as connected mode
            local_.Clear();
            
            p->SetConnectionID(ID());
            ReplaceTransceiver(p);
            bResult = p->Start();
        }
        
        if (bResult == false) {
            TransportImpl::GetInstance()->RequestReset(p->ResourceType(),
                                                       p->ID(),
                                                       p);
        }
    }
    
    return bResult;
}

bool ConnectionImpl::RetryIfNetworkChanged()
{
    //
    // This is only supported for native UDP application
    //
    if (origType_ != CT_UDP) {
        DLOG("not supported for " << toStr(origType_));
        return false;
    }
    
    bool bResult = false;
    bool network_changed = false;
    
    string local_ip = GetLocalIPAddress(remote_.IPString().c_str());
    if (local_ip.empty()) {
        MLOG("No local network interface found");
        // network disappeared wait until we have new network interface
        return true;
    }
    
    if (local_ip != local_.IPString()) {
        MLOG("Network changed from " << local_.IPString() << " to " <<
             local_ip);
        network_changed = true;
    }
    else {
        DLOG("Network is not changed: " << local_ip);
    }
    
    if (network_changed) {
        bResult = Failover(true); // try same transceiver again
    }
    
    return bResult;
}
    
ConnectionType ConnectionImpl::GetOriginalConnectionType() const
{
    return origType_;
}
    
bool ConnectionImpl::GetOriginalRemoteAddress(string& rRemote, uint16_t& rPort)
{
    bool bResult = false;
    
    if (origRemote_.Valid()) {
        rRemote = origRemote_.IPString();
        rPort   = origRemote_.Port();
        bResult = true;
    }
    else if (!domainRemote_.empty()) {
        rRemote = domainRemote_;
        rPort   = origRemote_.Port();
        bResult = true;
    }
    else if (remote_.Valid()) {
        rRemote = remote_.IPString();
        rPort   = remote_.Port();
        bResult = true;
    }
    
    return bResult;
}
    
void ConnectionImpl::ReplaceTransceiver(Transceiver* p)
{
    // transLock_ is to protect pTransceiver as it has caused
    // some weird crash in linux while Send() and ReplaceTransciever() are called.
    // We don't need to protect method where transport thread is exclusively using
    // but only the API that app thread is entering namely;
    // Send(), GeSendQInfo(), GetSendRetryCount()
    MutexLock scoped(&transLock_);
    
    if (pTransceiver_ != NoTransceiver::GetInstance()) {
        TransportImpl::GetInstance()->RequestReset(pTransceiver_->ResourceType(),
                                                   pTransceiver_->ID(),
                                                   pTransceiver_);
        pTransceiver_->SetConnectionID(INVALID_ID);
    }
    
    if (InState(TERMINATED) && (p != NoTransceiver::GetInstance())) {
        MLOG("Reconnected to new transceiver " << p->ID());
        state_ = CONNECTED;
    }
    
    pTransceiver_ = p;

    // if frame mode is on then enable it for new tcp transceiver
    if (bWYSWYG_) {
        if (pTransceiver_->ConnType() == CT_TCP) {
            if (TcpTransceiver* p_tcp =
                dynamic_cast<TcpTransceiver*>(pTransceiver_)) {
                p_tcp->EnableTcpFramer();
            }
        }
    }
}
   
void ConnectionImpl::EnablePortReservation(bool flag)
{
    bReservePort_ = flag;
}
    
bool ConnectionImpl::UsePortReservation()
{
    return bReservePort_;
}

bool ConnectionImpl::InState(ConnectionImpl::State flag)
{
    return ((state_ & flag) == flag);
}
    
void ConnectionImpl::SetState(ConnectionImpl::State flag)
{
    state_ |= flag;
}

ConnectionImpl::QueueSizeType ConnectionImpl::GetSizeType(uint32_t bufSize)
{
    if (bufSize <= 64) {
        return SIZE_64;
    }
    else if (bufSize <= 256) {
        return SIZE_256;
    }
    else if (bufSize <= 1024) {
        return SIZE_1024;
    }
    else if (bufSize <= 2048) {
        return SIZE_2048;
    }
    else if (bufSize <= 32000) {
        return SIZE_32000;
    }
    else if (bufSize <= 65000) {
        return SIZE_65000;
    }
    else if (bufSize <= 262000) {
        return SIZE_262000;
    }
    
    return MAX_QUEUE_SIZE;
}

uint32_t ConnectionImpl::SizeArray[ConnectionImpl::MAX_QUEUE_SIZE]
    = { 0, 64, 256, 1024, 2048, 32000, 65000, 262000 };
    
NetworkBuffer::Ptr ConnectionImpl::GetBuffer(uint32_t bufSize)
{
    NetworkBuffer::Ptr sp_buf;
    
    NetworkBuffer* p_buf = 0;
    
    QueueSizeType size_type = GetSizeType(bufSize);
    
    if (size_type != MAX_QUEUE_SIZE) {
        MutexLock scoped(&rcqLock_);
        if (!recycleQ_[size_type].empty()) {
            p_buf = recycleQ_[size_type].front();
            recycleQ_[size_type].pop();
        }
        bufNum_++;
    }
    
    if (!p_buf) {
        MLOG("Requested " << bufSize << "B - creating buffer (" <<
             SizeArray[size_type] << "B) num: " << bufNum_ );
        
        uint32_t real_size =
            (size_type != MAX_QUEUE_SIZE ? SizeArray[size_type] : bufSize);
        p_buf = new NetworkBuffer(real_size);
        p_buf->appID_ = ID(); // mark the connection ID for release
        bufAlloc[size_type]++;
    }

    if (p_buf) {
        p_buf->setSize(bufSize);
        sp_buf.reset(p_buf, HandleReleasedBuffer);
    }
    
    return sp_buf;
}

NetworkBuffer::Ptr ConnectionImpl::GetBuffer(Buffer::Ptr spBuf)
{
    NetworkBuffer::Ptr sp_buf;
    
    NetworkBuffer* p_buf = 0;
    
    {
        MutexLock scoped(&rcqLock_);
        if (!recycleQ_[SHALLOW_COPY].empty()) {
            p_buf = recycleQ_[SHALLOW_COPY].front();
            recycleQ_[SHALLOW_COPY].pop();
        }
        bufNum_++;
    }
    
    if (!p_buf) {
        MLOG("Requested shallow copy - creating shallow num: " << bufNum_);
        p_buf = new NetworkBuffer(spBuf);
        p_buf->appID_ = ID(); // mark the connection ID for release
        bufAlloc[SHALLOW_COPY]++;
    }
    else {
        p_buf->setAsShallowCopy(spBuf);
    }
    
    if (p_buf) {
        sp_buf.reset(p_buf, HandleReleasedBuffer);
    }
    
    return sp_buf;
}
    
void ConnectionImpl::AddBuffer(NetworkBuffer* pBuf)
{
    if (!pBuf->bShallowCopy_) {
        QueueSizeType size_type = GetSizeType(pBuf->getRawSize());
        if (size_type != MAX_QUEUE_SIZE) {
            pBuf->rewind();
            pBuf->setOffset(0);
            MutexLock scoped(&rcqLock_);
            recycleQ_[size_type].push(pBuf);
        }
        else {
            // release buffer that isn't expected
            delete pBuf;
        }
    }
    else {
        pBuf->releaseRawBuffer();
        MutexLock scoped(&rcqLock_);
        recycleQ_[SHALLOW_COPY].push(pBuf);
    }
}
    
void ConnectionImpl::HandleReleasedBuffer(NetworkBuffer* pBuf)
{
    // retrieve connection ID
    if (pBuf->appID_ == INVALID_ID) {
        _WLOG_("invalid app id");
        delete pBuf;
        return;
    }
    
    if (ConnectionImpl* p =
            ResourceMgr::GetInstance()->GetConnection(pBuf->appID_)) {
        p->AddBuffer(pBuf);
    }
    else {
        _WLOG_("deleting " << (pBuf->bShallowCopy_ ? "shallow " : "") <<
               "buf " << pBuf->getRawSize() << "B on inactive c" << pBuf->appID_);
        delete pBuf;
    }
}
    
bool is_end_event(EventType type)
{
    return (type == ET_DISCONNECTED ||
            type == ET_REFUSED ||
            type == ET_FAILED);
}

} // namespace fuze
