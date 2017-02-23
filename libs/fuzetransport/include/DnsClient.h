//
//  DnsClient.h
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef DnsClient_h
#define DnsClient_h

#include "Common.h"

namespace fuze {
    
// Perform DNS lookup on domain address
//
//  Synchronous API
//
string         TranslateToIP(const string& rAddress);
vector<string> TranslateToIPs(const string& rAddress);

namespace dns {
    
    struct Record
    {
        typedef fuze_shared_ptr<Record> Ptr;
        typedef std::list<Ptr>          List;
        
        enum Type { A, SRV, NAPTR, MAX_NUM };
        
        string    domain_;
        Type      type_;
        uint32_t  class_;
        uint32_t  ttl_;
        int64_t   expire_; // added to track time to be expired
        
        bool operator==(const Record& rRhs);
        
        virtual ~Record() {}
    };
    
    struct A : public Record
    {
        typedef fuze_shared_ptr<A> Ptr;
        
        string  hostName_;
        bool    bad_; // internal usage
    };
    
    struct SRV : public Record
    {
        typedef fuze_shared_ptr<SRV> Ptr;
        
        uint32_t  priority_;
        uint32_t  weight_;
        uint32_t  port_;
        string    name_;
    };
    
    struct NAPTR : public Record
    {
        typedef fuze_shared_ptr<NAPTR> Ptr;
        
        uint32_t  order_;
        uint32_t  pref_;
        string    flag_;
        string    services_;
        string    regexp_;
        string    replacement_;
    };
    
    class Resolver
    {
    public:
        typedef fuze_shared_ptr<Resolver> Ptr;
        
        static Ptr   Create();
        
        static void  Init();
        static void  Terminate();
        
        // set DNS lookup request (multiple queries can be set)
        virtual void SetQuery(const string& rDomain, Record::Type type) = 0;
        
        // perform DNS query
        virtual Record::List Query(int timeout = 30) = 0;
        
        virtual ~Resolver() {}
    };
    
    void MarkAsBadCache(const string& rAddress);
    void ClearCache();
    void PrintRecord(const dns::Record::Ptr& rspRec);
    
    const char* toStr(Record::Type type);
    
} // namespace dns

//
//  Asynchronous API
//
class DnsObserver
{
public:
    virtual void OnDnsReply(dns::Record::List& rReplies, void* pArg) = 0;
    
    virtual ~DnsObserver() {}
};

void QueryDnsServer(const string&      rAddress,
                    dns::Record::Type  type,
                    DnsObserver*       pObserver,
                    void*              pArg);

class DebugOut;

DebugOut& operator<<(DebugOut& rOut, dns::Record::Ptr spRecord);

} // namespace fuze
    
#endif /* DnsClient_h */
