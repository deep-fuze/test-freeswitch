//
//  DnsResolver.h
//  FuzeTransport
//
//  Created by Tim Na on 3/10/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//

#ifndef DnsResolver_h
#define DnsResolver_h

#include <Transport.h>
#include <Thread.h>
#include <Semaphore.h>
#include <ares.h>
#include <list>

namespace fuze {
namespace dns {

using std::string;
using std::vector;
using std::list;

void SetDnsCache(Record::List& rList);

class ResolverImpl : public Resolver
{
public:
    typedef fuze_shared_ptr<ResolverImpl> Ptr;
    
    ResolverImpl();
    ~ResolverImpl();
    
    virtual void SetQuery(const string& rDomain,
                          Record::Type  type);
    virtual Record::List Query(int timeout = 30);
    
private:
    
    static void OnReply(void*    pArg,
                        int      status,
                        int      timeouts,
                        uint8_t* pBuf,
                        int      len);
    
    void SetReplies(Record::List newReplies);
    
    // for parallel queries
    struct QueryData
    {
        string         domain_;
        Record::Type   type_;
        ResolverImpl*  pResolver_;
    };
    
    ares_channel       channel_;
    Record::List       replies_;
    vector<QueryData>  queries_;
};

class AsyncResolver : public Runnable
{
public:
    typedef fuze_shared_ptr<AsyncResolver> Ptr;
    
    AsyncResolver();
    virtual ~AsyncResolver();
    
    void SetQuery(const string& rDomain,
                  Record::Type  type_,
                  DnsObserver*  pObserver,
                  void*         pArg);
    
private:
    
    virtual void Run();
    
    static void OnReply(void*    pArg,
                        int      status,
                        int      timeouts,
                        uint8_t* pBuf,
                        int      len);
    
    struct QueryData
    {
        string        domain_;
        Record::Type  type_;
        DnsObserver*  pObserver_;
        void*         pArg_;
    };
    
    static void DnsFallback(QueryData* pData);
    
private:
    
    QueryData* GetQueryData();
    void       ResetChannel();
    
    ares_channel       channel_;
    
    bool               running_;
    
    Thread             thread_;
    Semaphore          semaphore_;

    list<QueryData*>   queryData_;
    MutexLock          qLock_;
    
    string             localIP_;
    int64_t            lastTime_;
};
    
} // namespace dns
} // namespace fuze
    
#endif // DnsResolver_h
