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
#endif

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Con[b" << baseID_ << ":c" << ID() << ":" << name_ << "] " << __FUZE_FUNC__ << ": " << B)

namespace fuze {

NoTransceiver NoTransceiver::sInstance_;

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
    , connType_(CT_INVALID)
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
        bufAlloc[i] = 0;
    }
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
        connType_ = pTransceiver_->ConnType();
        
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

        MLOG("Starting " << toStr(connType_));
        
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
        int buf_cnt = 0;
        {
            memset(buf_free, 0, sizeof(buf_free));
            
            MutexLock scoped(&poolLock_);
            for (int i = 0; i < MAX_QUEUE_SIZE; ++i) {
                while (!bufPool_[i].empty()) {
                    buf_free[i]++;
                    buf_cnt++;
                    if (i == BUFFER_SHELL) {
                        delete (NetworkBuffer*)bufPool_[i].front();
                    }
                    else {
                        delete (RawMemory*)bufPool_[i].front();
                    }
                    bufPool_[i].pop();
                }
            }
        }
        
        MLOG("MemoryStat: " <<
             "shallow (" << buf_free[BUFFER_SHELL] << "/" << bufAlloc[BUFFER_SHELL] <<
             ") 64 (" << buf_free[SIZE_64] << "/" << bufAlloc[SIZE_64] <<
             ") 256 (" << buf_free[SIZE_256] << "/" << bufAlloc[SIZE_256] <<
             ") 1024 (" << buf_free[SIZE_1024] << "/" << bufAlloc[SIZE_1024] <<
             ") 2048 (" << buf_free[SIZE_2048] << "/" << bufAlloc[SIZE_2048] <<
             ") 32000 (" << buf_free[SIZE_32000] << "/" << bufAlloc[SIZE_32000] <<
             ") 65000 (" << buf_free[SIZE_65000] << "/" << bufAlloc[SIZE_65000] <<
             ") 262000 (" << buf_free[SIZE_262000] << "/" << bufAlloc[SIZE_262000] <<
             ") buf count: " << buf_cnt << "/" << bufNum_);
        
        bufNum_ = 0;

        for (int i = 0; i < MAX_QUEUE_SIZE; ++i) {
            bufAlloc[i] = 0;
        }
        
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
    
    string local_addr = IP;
    
    // check local ip type and correct if needed
    const string& local_ip = GetLocalIPAddress();
    if (!local_ip.empty() &&
        GetIPType(local_addr.c_str()) != GetIPType(local_ip.c_str())) {
        MLOG("adjusting IP " << local_addr << " -> " << local_ip);
        local_addr = local_ip;
    }
    
    MLOG(local_ << " -> " << local_addr << " (" << port << ")");
    
    if (local_.SetIP(local_addr.c_str()) && local_.SetPort(port)) {
        result = true;
    }
    else {
        ELOG("Invalid IP address: " << local_addr);
    }
    
    return result;
}
    
bool ConnectionImpl::SetRemoteAddress(const string& IP, uint16_t port)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    MLOG(remote_ << " -> " << IP << " (" << port << ")");

    // application may have used domain name instead
    string remote_addr = IP;
    
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
    else {
        // check local ip type and correct if needed
        const string& local_ip = GetLocalIPAddress();
        if (!local_ip.empty() &&
            GetIPType(remote_addr.c_str()) != GetIPType(local_ip.c_str())) {
            remote_addr = IPv4toIPv6(remote_addr);
            MLOG("Remote " << IP << " changed to " << remote_addr);
            remote_.SetIP(remote_addr.c_str());
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
    
    if (connType_ == CT_TCP) {
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

bool ConnectionImpl::Send(const uint8_t* buf, size_t size, uint16_t remotePort)
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
    if (!remotePort) return pTransceiver_->Send(buf, size);
    Address remoteAddr = remote_;
    remoteAddr.SetPort(remotePort);
    return pTransceiver_->Send(buf, size, remoteAddr);
}

bool ConnectionImpl::GetConnectedType(ConnectionType& rType)
{
    if (IsActive() == false) {
        ELOG(GetStatusString());
        return false;
    }
    
    rType = connType_;
    
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
    
    if (connType_ == CT_TCP || connType_ == CT_TLS) {
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

void ConnectionImpl::GetSendStat(uint32_t &rCount, int64_t &rBytes)
{
    rCount = sendStat_.count_;
    rBytes = sendStat_.totalBytes_;
}

void ConnectionImpl::GetRecvStat(uint32_t &rCount, int64_t &rBytes)
{
    rCount = recvStat_.count_;
    rBytes = recvStat_.totalBytes_;
}
    
uint32_t ConnectionImpl::GetSendRetryCount()
{
    uint32_t retry = 0;
    
    MutexLock scoped(&transLock_);
    
    if (connType_ == CT_TCP || connType_ == CT_TLS) {
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
        connType_ = pTransceiver_->ConnType();
        
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
    catch (const std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
    
    // it's possible that while we were in app callback, connection
    // has been reset by application
    if (!IsActive()) return;
    
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
        
        if (connType_ == CT_UDP) {
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
        else if (connType_ == CT_TCP) {
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
    
    if (spWorker_) {
        spWorker_->SetWork(this);
    }
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
    catch (const std::exception& ex) {
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
    
    if (spWorker_) {
        spWorker_->SetWork(this);
    }
}

void ConnectionImpl::DeliverRateData(fuze::ConnectionImpl::RateData &rRate)
{
    try {
        if (wpObserver_.expired()) {
            MutexLock scoped(&conLock_);
            if (pObserver_) {
                pObserver_->OnRateData(pAppContext_,
                                       rRate.type_, rRate.rate_, rRate.delta_);
            }
        }
        else {
            if (ConnectionObserver::Ptr sp = wpObserver_.lock()) {
                sp->OnRateData(pAppContext_,
                               rRate.type_, rRate.rate_, rRate.delta_);
            }
        }
    }
    catch (const std::exception& ex) {
        ELOG("exception - " << ex.what());
    }
    catch (...) {
        ELOG("unknown exception");
    }
}
    
uint32_t ConnectionImpl::OnBytesSent(uint32_t bytesSent)
{
    int64_t curr_time = GetTimeMs();

    AddSendStat(bytesSent, curr_time);
    AddRecvStat(0, curr_time); // check recv stat in case not active
    
    if (sendStat_.count_ <= 5) {
        MLOG(bytesSent << "B (count: " << sendStat_.count_ << ")");
    }
    
    return sendStat_.count_;
}

uint32_t ConnectionImpl::OnBytesRecv(uint32_t bytesRecv)
{
    int64_t curr_time = GetTimeMs();
    
    AddRecvStat(bytesRecv, curr_time);
    AddSendStat(0, curr_time); // check send stat in case not active
    
    if (recvStat_.count_ == 1) {
        if (connType_ == CT_UDP) {
            OnEvent(ET_CONNECTED, "received first packet");
        }
    }
    
    if (recvStat_.count_ <= 5) {
        MLOG(bytesRecv << "B (count: " << recvStat_.count_ << ")");
    }
    
    return recvStat_.count_;
}

void ConnectionImpl::AddSendStat(uint32_t bytesSent, int64_t currTime)
{
    int rate = sendStat_.AddBytes(bytesSent, currTime);
    
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
            if (!sendStat_.lastSent_) {
                sendStat_.lastSent_ = currTime;
            }
            uint16_t diff = uint16_t(currTime - sendStat_.lastSent_);
            OnRateData(RT_LOCAL_SEND, send_rate, diff);
            sendStat_.lastSent_ = currTime;
        }
    }
}

void ConnectionImpl::AddRecvStat(uint32_t bytesRecv, int64_t currTime)
{
    int rate = recvStat_.AddBytes(bytesRecv, currTime);
    
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
            if (!recvStat_.lastSent_) {
                recvStat_.lastSent_ = currTime;
            }
            uint16_t diff = uint16_t(currTime - recvStat_.lastSent_);
            OnRateData(RT_LOCAL_RECV, recv_rate, diff);
            recvStat_.lastSent_ = currTime;
        }
    }
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
                bool retry_same_type = (connType_ == CT_UDP ? false : true);
                if (Failover(retry_same_type)) {
                    if (connType_ == CT_UDP) {
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

    ConnectionType     type = connType_;
    TcpTxrxState::Type state_type = TcpTxrxState::SETUP_TLS;
    string             event_str(toStr(connType_));
    
    if (bRetrySameType) {
        if ((connType_ == CT_TCP) || (connType_ == CT_TLS)) {
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
        
        if (connType_ == CT_UDP) {
            type = CT_TCP;
            state_type = TcpTxrxState::SETUP_TLS;
            remote_.SetPort(Server::PORT);
            MLOG("transition UDP -> TLS [" << toStr(state_type) << "]");
        }
        else if ((connType_ == CT_TCP) || (connType_ == CT_TLS)) {
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
            ELOG("can't failover connection type: " << toStr(connType_));
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
    connType_     = pTransceiver_->ConnType();

    // if frame mode is on then enable it for new tcp transceiver
    if (bWYSWYG_) {
        if (connType_ == CT_TCP) {
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
    
NetworkBuffer::Ptr ConnectionImpl::GetBufferShell()
{
    NetworkBuffer::Ptr sp_buf;
    NetworkBuffer*     p_buf = 0;
    
    {
        MutexLock scoped(&poolLock_);
        if (!bufPool_[BUFFER_SHELL].empty()) {
            p_buf = (NetworkBuffer*)bufPool_[BUFFER_SHELL].front();
            bufPool_[BUFFER_SHELL].pop();
        }
    }
    
    if (!p_buf) {
        p_buf = new NetworkBuffer; // create empty buffer shell
        p_buf->appID_ = ID(); // mark the connection ID for release
        bufAlloc[BUFFER_SHELL]++;
    }
    
    sp_buf.reset(p_buf, HandleReleasedBuffer);
    
    return sp_buf;
}
    
NetworkBuffer::Ptr ConnectionImpl::GetBuffer(uint32_t bufSize)
{
    RawMemory::Ptr sp_mem;
    RawMemory* p_mem = 0;
    
    QueueSizeType size_type = GetSizeType(bufSize);
    
    if (size_type != MAX_QUEUE_SIZE) {
        MutexLock scoped(&poolLock_);
        if (!bufPool_[size_type].empty()) {
            p_mem = (RawMemory*)bufPool_[size_type].front();
            bufPool_[size_type].pop();
        }
    }
    
    if (!p_mem) {
        uint32_t real_size =
            (size_type != MAX_QUEUE_SIZE ? SizeArray[size_type] : bufSize);
        p_mem = new RawMemory(bufSize, real_size);
        p_mem->setAppID(ID()); // mark the connection ID for release
        bufAlloc[size_type]++;
        if (++bufNum_ <= 100 || (bufAlloc[size_type] % 10 == 0)) {
            MLOG(bufSize << "B (" << SizeArray[size_type] <<
                 "B created) num: " << bufNum_);
        }
    }
    else {
        p_mem->setSize(bufSize);
    }
    
    sp_mem.reset(p_mem, HandleReleasedMemory);

    NetworkBuffer::Ptr sp_buf = GetBufferShell();
    sp_buf->init(sp_mem);
    
    return sp_buf;
}

NetworkBuffer::Ptr ConnectionImpl::GetBuffer(Buffer::Ptr spBuf)
{
    NetworkBuffer::Ptr sp_buf = GetBufferShell();
    sp_buf->setAsShallowCopy(spBuf);
    return sp_buf;
}
    
void ConnectionImpl::AddBuffer(NetworkBuffer* pBuf)
{
    pBuf->reset();
    MutexLock scoped(&poolLock_);
    bufPool_[BUFFER_SHELL].push(pBuf);
}
    
void ConnectionImpl::AddMemory(RawMemory* pMem)
{
    QueueSizeType size_type = GetSizeType(pMem->getRealSize());
    if (size_type != MAX_QUEUE_SIZE) {
        MutexLock scoped(&poolLock_);
        bufPool_[size_type].push(pMem);
    }
    else { // release buffer that isn't expected
        delete pMem;
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
        _DLOG_("deleting buffer shell on inactive c" << pBuf->appID_);
        delete pBuf;
    }
}

void ConnectionImpl::HandleReleasedMemory(RawMemory* pMem)
{
    // retrieve connection ID
    int app_id = pMem->getAppID();
    
    if (app_id == INVALID_ID) {
        _WLOG_("invalid app id");
        delete pMem;
        return;
    }
    
    if (ConnectionImpl* p =
            ResourceMgr::GetInstance()->GetConnection(app_id)) {
        p->AddMemory(pMem);
    }
    else {
        _DLOG_("deleting raw memory " << pMem->getRealSize() <<
               "B on inactive c" << app_id);
        delete pMem;
    }
}
    
bool is_end_event(EventType type)
{
    return (type == ET_DISCONNECTED ||
            type == ET_REFUSED ||
            type == ET_FAILED);
}

} // namespace fuze
