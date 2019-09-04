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
#include <ares.h>

namespace fuze {
namespace dns {

using std::string;
using std::vector;
    
class ResolverImpl : public Resolver
{
public:
    typedef fuze_shared_ptr<ResolverImpl> Ptr;
    
    ResolverImpl();
    ~ResolverImpl();
    
    virtual Record::List Query(const string& rDomain,
                               Record::Type  type);
    
private:
    
    static void OnReply(void*    pArg,
                        int      status,
                        int      timeouts,
                        uint8_t* pBuf,
                        int      len);
    
    void ProcessQuery();

    ares_channel  channel_;
};
    
} // namespace dns
} // namespace fuze
    
#endif // DnsResolver_h
