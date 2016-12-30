//
//  DnsResolver.cpp
//  FuzeTransport
//
//  Created by Tim Na on 3/10/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#include <DnsResolver.h>
#include <TransportImpl.h>
#include <Log.h>

#define DNS__16BIT(p)  ((unsigned short)((unsigned int) 0xffff & \
                        (((unsigned int)((unsigned char)(p)[0]) << 8U) | \
                        ((unsigned int)((unsigned char)(p)[1])))))

/*
 * Macro DNS__32BIT reads a network long (32 bit) given in network
 * byte order, and returns its value as an unsigned int.
 */
#define DNS__32BIT(p)  ((unsigned int) \
                        (((unsigned int)((unsigned char)(p)[0]) << 24U) | \
                        ((unsigned int)((unsigned char)(p)[1]) << 16U) | \
                        ((unsigned int)((unsigned char)(p)[2]) <<  8U) | \
                        ((unsigned int)((unsigned char)(p)[3]))))

#define DNS__SET16BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 8) & 0xff)), \
                                ((p)[1] = (unsigned char)((v) & 0xff)))

#define DNS__SET32BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 24) & 0xff)), \
                                ((p)[1] = (unsigned char)(((v) >> 16) & 0xff)), \
                                ((p)[2] = (unsigned char)(((v) >> 8) & 0xff)), \
                                ((p)[3] = (unsigned char)((v) & 0xff)))

/* Macros for parsing a DNS header */
#define DNS_HEADER_QID(h)               DNS__16BIT(h)
#define DNS_HEADER_QR(h)                (((h)[2] >> 7) & 0x1)
#define DNS_HEADER_OPCODE(h)            (((h)[2] >> 3) & 0xf)
#define DNS_HEADER_AA(h)                (((h)[2] >> 2) & 0x1)
#define DNS_HEADER_TC(h)                (((h)[2] >> 1) & 0x1)
#define DNS_HEADER_RD(h)                ((h)[2] & 0x1)
#define DNS_HEADER_RA(h)                (((h)[3] >> 7) & 0x1)
#define DNS_HEADER_Z(h)                 (((h)[3] >> 4) & 0x7)
#define DNS_HEADER_RCODE(h)             ((h)[3] & 0xf)
#define DNS_HEADER_QDCOUNT(h)           DNS__16BIT((h) + 4)
#define DNS_HEADER_ANCOUNT(h)           DNS__16BIT((h) + 6)
#define DNS_HEADER_NSCOUNT(h)           DNS__16BIT((h) + 8)
#define DNS_HEADER_ARCOUNT(h)           DNS__16BIT((h) + 10)

/* Macros for parsing the fixed part of a DNS question */
#define DNS_QUESTION_TYPE(q)            DNS__16BIT(q)
#define DNS_QUESTION_CLASS(q)           DNS__16BIT((q) + 2)

/* Macros for constructing the fixed part of a DNS question */
#define DNS_QUESTION_SET_TYPE(q, v)     DNS__SET16BIT(q, v)
#define DNS_QUESTION_SET_CLASS(q, v)    DNS__SET16BIT((q) + 2, v)

/* Macros for parsing the fixed part of a DNS resource record */
#define DNS_RR_TYPE(r)                  DNS__16BIT(r)
#define DNS_RR_CLASS(r)                 DNS__16BIT((r) + 2)
#define DNS_RR_TTL(r)                   DNS__32BIT((r) + 4)
#define DNS_RR_LEN(r)                   DNS__16BIT((r) + 8)

/* Macros for constructing the fixed part of a DNS resource record */
#define DNS_RR_SET_TYPE(r, v)           DNS__SET16BIT(r, v)
#define DNS_RR_SET_CLASS(r, v)          DNS__SET16BIT((r) + 2, v)
#define DNS_RR_SET_TTL(r, v)            DNS__SET32BIT((r) + 4, v)
#define DNS_RR_SET_LEN(r, v)            DNS__SET16BIT((r) + 8, v)

#define NS_HFIXEDSZ     12    /* #/bytes of fixed data in header */
#define HFIXEDSZ         NS_HFIXEDSZ

#define NS_QFIXEDSZ     4     /* #/bytes of fixed data in query */
#define QFIXEDSZ         NS_QFIXEDSZ

#define NS_RRFIXEDSZ    10    /* #/bytes of fixed data in r record */
#define RRFIXEDSZ        NS_RRFIXEDSZ

namespace fuze {
namespace dns {

namespace {
    
const char* opcodes[] =
{
    "QUERY", "IQUERY", "STATUS", "(reserved)", "NOTIFY",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)",
    "UPDATEA", "UPDATED", "UPDATEDA", "UPDATEM", "UPDATEMA",
    "ZONEINIT", "ZONEREF"
};

const char* rcodes[] =
{
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)", "(unknown)",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)", "NOCHANGE"
};
    
const char* classString(int type)
{
    if (type == 1) {
        return "IN";
    }
    return "UNEXPECTED";
}

const char* typeString(int type)
{
    switch (type)
    {
    case 1:  return "A";
    case 33: return "SRV";
    case 35: return "NAPTR";
    default: return "UNEXPECTED";
    }
}
    
const uint8_t* QueryInfo(const uint8_t* pData, const uint8_t* pBuf, int bufLen)
{
    char* name = 0;
    int   status = 0;
    long  len = 0;
    
    /* Parse the question name. */
    status = ares_expand_name(pData, pBuf, bufLen, &name, &len);
    if (status != ARES_SUCCESS) {
        _WLOG_(ares_strerror(status));
        return 0;
    }
    pData += len;
    
    /* Make sure there's enough data after the name for the fixed part
     * of the question.
     */
    if (pData + QFIXEDSZ > pBuf + bufLen)
    {
        _WLOG_(ares_strerror(status));
        ares_free_string(name);
        return 0;
    }
    
    /* Parse the question type and class. */
    int type = DNS_QUESTION_TYPE(pData);
    int dnsclass = DNS_QUESTION_CLASS(pData);
    pData += QFIXEDSZ;
    
    /* Display the question, in a format sort of similar to how we will
     * display RRs.
     */
    _MLOG_(name << " " << classString(dnsclass) << " " << typeString(type))
    ares_free_string(name);
    
    return pData;
}

const uint8_t* HandleDnsReply(void* pArg, const uint8_t* pData, const uint8_t* pBuf, int bufLen)
{
    long len = 0;
    char addr[46] = {0};
    
    union
    {
        uint8_t* as_uchar;
        char*    as_char;
    } name;
    
    /* Parse the RR name. */
    int status = ares_expand_name(pData, pBuf, bufLen, &name.as_char, &len);
    if (status != ARES_SUCCESS) {
        _WLOG_(ares_strerror(status));
        return 0;
    }
    
    pData += len;
    
    /* Make sure there is enough data after the RR name for the fixed
     * part of the RR.
     */
    if (pData + RRFIXEDSZ > pBuf + bufLen) {
        _WLOG_(ares_strerror(status));
        ares_free_string(name.as_char);
        return 0;
    }
    
    /* Parse the fixed part of the RR, and advance to the RR data
     * field. */
    int type     = DNS_RR_TYPE(pData);
    int dnsclass = DNS_RR_CLASS(pData);
    int ttl      = DNS_RR_TTL(pData);
    int dlen     = DNS_RR_LEN(pData);
    
    pData += RRFIXEDSZ;
    if (pData + dlen > pBuf + bufLen) {
        ares_free_string(name.as_char);
        return 0;
    }
    string domain = name.as_char;
    ares_free_string(name.as_char);
    
    /* Display the RR data.  Don't touch pData. */
    switch (type)
    {
    case 1:
        if (Record::List* p_list = (Record::List*)pArg) {
            /* The RR data is a four-byte Internet address. */
            if (dlen != 4) return 0;
            
            A::Ptr sp(new A);
            
            sp->domain_   = domain;
            sp->type_     = Record::A;
            sp->class_    = dnsclass;
            sp->ttl_      = ttl;
            sp->hostName_ = ares_inet_ntop(AF_INET, pData, addr, sizeof(addr));
            
            p_list->push_back(sp);
            
            _DLOG_("[A] " << domain << " " << ttl << " " <<
                   classString(dnsclass) << " " << typeString(type) << " -> " <<
                   sp->hostName_);
        }
        break;
    case 33:
        if (Record::List* p_list = (Record::List*)pArg) {
            /* The RR data is three two-byte numbers representing the
             * priority, weight, and port, followed by a domain name.
             */
            SRV::Ptr sp(new SRV);
            
            sp->domain_   = domain;
            sp->type_     = Record::SRV;
            sp->class_    = dnsclass;
            sp->ttl_      = ttl;
            sp->priority_ = (uint32_t)DNS__16BIT(pData);
            sp->weight_   = (uint32_t)DNS__16BIT(pData + 2);
            sp->port_     = (uint32_t)DNS__16BIT(pData + 4);
            
            status = ares_expand_name(pData + 6, pBuf, bufLen, &name.as_char, &len);
            if (status != ARES_SUCCESS) {
                _WLOG_(ares_strerror(status));
                return 0;
            }
            sp->name_ = name.as_char;
            ares_free_string(name.as_char);
            
            p_list->push_back(sp);
            
            _DLOG_("[SRV] " << domain << " " << ttl << " " <<
                   classString(dnsclass) << " " << typeString(type) << " -> " <<
                   sp->name_ << ":" << sp->port_ << " priority: " <<
                   sp->priority_ << " weight: " << sp->weight_);
        }
        break;
    case 35:
        if (Record::List* p_list = (Record::List*)pArg) {
            NAPTR::Ptr sp(new NAPTR);
            
            sp->domain_ = domain;
            sp->type_   = Record::NAPTR;
            sp->class_  = dnsclass;
            sp->ttl_    = ttl;
            sp->order_  = (uint32_t)DNS__16BIT(pData);
            sp->pref_   = (uint32_t)DNS__16BIT(pData + 2);
            const uint8_t* p = pData + 4;
            status = ares_expand_string(p, pBuf, bufLen, &name.as_uchar, &len);
            if (status != ARES_SUCCESS) {
                _WLOG_(ares_strerror(status));
                return 0;
            }
            sp->flag_ = name.as_char;
            ares_free_string(name.as_char);
            p += len;
            
            status = ares_expand_string(p, pBuf, bufLen, &name.as_uchar, &len);
            if (status != ARES_SUCCESS) {
                _WLOG_(ares_strerror(status));
                return 0;
            }
            sp->services_ = name.as_char;
            ares_free_string(name.as_char);
            p += len;
            
            status = ares_expand_string(p, pBuf, bufLen, &name.as_uchar, &len);
            if (status != ARES_SUCCESS) {
                _WLOG_(ares_strerror(status));
                return 0;
            }
            sp->regexp_ = name.as_char;
            ares_free_string(name.as_char);
            p += len;
            
            status = ares_expand_name(p, pBuf, bufLen, &name.as_char, &len);
            if (status != ARES_SUCCESS) {
                _WLOG_(ares_strerror(status));
                return 0;
            }
            sp->replacement_ = name.as_char;
            ares_free_string(name.as_char);
            
            p_list->push_back(sp);
            
            _DLOG_("[NAPTR] " << domain << " " << ttl << " " <<
                   classString(dnsclass) << " " << typeString(type) << " -> " <<
                   sp->replacement_ << " " << sp->flag_ << " " <<
                   sp->services_ << " order: " << sp->order_ <<
                   ", pref: " << sp->pref_ << " " << sp->regexp_);
        }
        break;
    default:
        _DLOG_(type);
    }
    
    return pData + dlen;
}
    
int GetDnsType(Record::Type type)
{
    switch (type)
    {
    case Record::A:     return 1;
    case Record::SRV:   return 33;
    case Record::NAPTR: return 35;
    default:            return 0;
    }
}
    
bool SrvCompare(Record::Ptr spA, Record::Ptr spB)
{
    SRV::Ptr sp_a = fuze_dynamic_pointer_cast<SRV>(spA);
    SRV::Ptr sp_b = fuze_dynamic_pointer_cast<SRV>(spB);
    
    if (!sp_a) return false;
    if (!sp_b) return true;
    
    if (sp_a->priority_ != sp_b->priority_) {
        // lower priority preferred
        return (sp_a->priority_ < sp_b->priority_);
    }
    else {
        // higher weight preferred
        return (sp_a->weight_ > sp_b->weight_);
    }
}

bool NaptrCompare(Record::Ptr spA, Record::Ptr spB)
{
    NAPTR::Ptr sp_a = fuze_dynamic_pointer_cast<NAPTR>(spA);
    NAPTR::Ptr sp_b = fuze_dynamic_pointer_cast<NAPTR>(spB);
    
    if (!sp_a) return false;
    if (!sp_b) return true;
    
    if (sp_a->order_ != sp_b->order_) {
        // lower order preferred
        return (sp_a->order_ < sp_b->order_);
    }
    else {
        // lower preference preferred
        return (sp_a->pref_ < sp_b->pref_);
    }
}

} // unnamed namespace

void ResolverImpl::OnReply(void* pArg, int status, int timeouts, uint8_t* pBuf, int len)
{
    if (status != ARES_SUCCESS) {
        _WLOG_(ares_strerror(status));
        if (!pBuf) return;
    }
    
    if (len < HFIXEDSZ) {
        _WLOG_("Length too short " << len << "B < " << HFIXEDSZ << "B");
        return;
    }

    ResolverImpl* p_resolver = reinterpret_cast<ResolverImpl*>(pArg);
    
    /* Parse the answer header. */
    int id      = DNS_HEADER_QID(pBuf);
    int qr      = DNS_HEADER_QR(pBuf);
    int opcode  = DNS_HEADER_OPCODE(pBuf);
    int aa      = DNS_HEADER_AA(pBuf);
    int tc      = DNS_HEADER_TC(pBuf);
    int rd      = DNS_HEADER_RD(pBuf);
    int ra      = DNS_HEADER_RA(pBuf);
    int rcode   = DNS_HEADER_RCODE(pBuf);
    int qdcount = DNS_HEADER_QDCOUNT(pBuf);
    int ancount = DNS_HEADER_ANCOUNT(pBuf);
    int nscount = DNS_HEADER_NSCOUNT(pBuf);
    int arcount = DNS_HEADER_ARCOUNT(pBuf);
    
    /* Display the answer header. */
    _MLOG_("ID: " << id << " (" << len << "B) timeout: " << timeouts <<
           " flags: " << (qr ? "qr " : "") << (aa ? "aa " : "") <<
           (tc ? "tc " : "") << (rd ? "rd " : "") << (ra ? "ra " : "") <<
           "opcode: " << opcodes[opcode] << " rcode: " << rcodes[rcode] <<
           " Answers: " << ancount << " NS: " << nscount << " AR: " << arcount);
    
    /* Display the questions. */
    const uint8_t* pData = pBuf + HFIXEDSZ;
    for (int i = 0; i < qdcount; i++) {
        pData = QueryInfo(pData, pBuf, len);
        if (!pData) return;
    }
    
    // answers
    if (ancount > 0) {
        Record::List replies;
        for (int i = 0; i < ancount; i++) {
            pData = HandleDnsReply(&replies, pData, pBuf, len);
            if (!pData) return;
        }
        SetDnsCache(replies);
        p_resolver->SetReplies(replies);
    }
    
    // NS records
    if (nscount) {
        for (int i = 0; i < nscount; i++) {
            pData = HandleDnsReply(0, pData, pBuf, len);
            if (!pData) return;
        }
    }
    
    // additional records
    if (arcount > 0) {
        Record::List replies;
        for (int i = 0; i < arcount; i++) {
            pData = HandleDnsReply(&replies, pData, pBuf, len);
            if (!pData) return;
        }
        SetDnsCache(replies);
        p_resolver->SetReplies(replies);
    }
}

void ResolverImpl::SetReplies(Record::List newReplies)
{
    // make sure we don't add same result twice in the result
    for (auto& new_reply : newReplies) {
        bool duplicate = false;
        for (auto& reply : replies_) {
            if (*new_reply == *reply) {
                _DLOG_("duplicate found - ignored");
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        replies_.push_back(new_reply);
    }
}

void SetDnsCache(Record::List& rList)
{
    if (rList.size() > 0) {
        _DLOG_("Record: " << rList.size());
        
        Record::Ptr sp = rList.front();
        
        string domain = sp->domain_;
        
        if (sp->type_ == Record::SRV) {
            rList.sort(SrvCompare);
        }
        else if (sp->type_ == Record::NAPTR) {
            rList.sort(NaptrCompare);
        }
        
        TransportImpl::GetInstance()->SetDnsCache(rList);
    }
}
    
void Resolver::Init()
{
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        _ELOG_("ares_library_init: " << ares_strerror(status));
    }
}
    
void Resolver::Terminate()
{
    ares_library_cleanup();
}

Resolver::Ptr Resolver::Create()
{
    Resolver::Ptr sp(new ResolverImpl);
    return sp;
}
    
ResolverImpl::ResolverImpl()
{
    ares_init(&channel_);
    
    ares_options options;
    options.flags    = ARES_OPT_TIMEOUTMS;
    options.timeout  = 2000;
    options.servers  = 0;
    options.nservers = 0;
    int status = ares_init_options(&channel_, &options, ARES_OPT_FLAGS);
    if (status != ARES_SUCCESS) {
        _ELOG_("ares_init_options: " << ares_strerror(status));
    }
}

ResolverImpl::~ResolverImpl()
{
    ares_destroy(channel_);
}


void ResolverImpl::SetQuery(const string& rDomain, Record::Type type)
{
    _DLOG_(rDomain << " (" << toStr(type) << ")");
    
    QueryReq query;
    
    query.domain_ = rDomain;
    query.type_   = type;
    
    queries_.push_back(query);
}
    
Record::List ResolverImpl::Query(int timeout)
{
    if (queries_.size() > 1) {
        _MLOG_(queries_.size() << " queries (timeout: " << timeout << " sec)");
    }
    
    // clear replies if application is using same instance
    replies_.clear();

    bool do_query = false;
    
    for (auto& query : queries_) {
        
        // check cache first
        Record::List cache =
            TransportImpl::GetInstance()->GetDnsCache(query.domain_, query.type_);
                                                      
        if (!cache.empty()) {
            for (auto& it : cache) {
                replies_.push_back(it);
            }
        }
        else {
            do_query = true;
            ares_query(channel_, query.domain_.c_str(), 1,
                       GetDnsType(query.type_), OnReply, this);
        }
    }
    
    // if there is no cache available then do query
    if (do_query) {
        ProcessQuery(timeout);
    }
    
    // clear queries
    queries_.clear();
    
    return replies_;
}
    
void ResolverImpl::ProcessQuery(int timeout)
{
    /* Wait for all queries to complete. */
    timeval tv;
    fd_set read_fds, write_fds;
    
    // set the absolute limit to the DNS look up
    int64_t app_timeout = GetTimeMs() + (timeout * 1000);
    
    for (;;) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int nfds = ares_fds(channel_, &read_fds, &write_fds);
        if (nfds == 0) {
            break;
        }
        
        timeval* p_tv = ares_timeout(channel_, 0, &tv);
        
        _MLOG_("Waiting for DNS reply (timeout: " << tv.tv_sec <<
               "." << tv.tv_usec/1000 << " seconds)");
        
        // if c-ares returned 0 for wait time then set 1 second as mininum
        if (tv.tv_sec == 0) {
            tv.tv_sec  = 1;
            tv.tv_usec = 0;
        }
        
        if (timeout != 0) {
            
            // calculate the app timeout
            int64_t curr_time = GetTimeMs();
            if (curr_time >= app_timeout) {
                _MLOG_("App timeout reached");
                break;
            }
            
            int app_time = int(app_timeout - curr_time);
            app_time /= 1000;
            if (app_time == 0) app_time = 1;
            
            if (tv.tv_sec >= app_time) {
                tv.tv_sec  = app_time;
                tv.tv_usec = 0;
                _MLOG_("Query timeout reset to " << timeout << " seconds");
            }
        }
        
        int ret = select(nfds, &read_fds, &write_fds, 0, p_tv);
        if (ret < 0) {
            _WLOG_("select fail");
            break;
        }
        else if (ret == 0) {
            _DLOG_("Timed out after " << tv.tv_sec <<
                   "." << tv.tv_usec/1000 << " seconds");
            if (GetTimeMs() >= app_timeout) {
                _MLOG_("App timeout reached");
                break;
            }
        }
        
        _DLOG_("Received an event");
        ares_process(channel_, &read_fds, &write_fds);
    }
}
    
} // namespace dns
} // namespace fuze
