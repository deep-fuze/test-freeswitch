//
//  DnsFileCache.cpp
//  FuzeTransport
//
//  Created by Tim Na on 5/3/17.
//  Copyright © 2017 Fuze. All rights reserved.
//
#import <Foundation/Foundation.h>
#include <string>

namespace fuze {

void SetDnsFileCache(std::string cache)
{
    NSString* p_ns_str = @(cache.c_str());
    NSUserDefaults* p_default = [NSUserDefaults standardUserDefaults];
    [p_default setObject:p_ns_str forKey:@"DNS_CACHE"];
}

void GetDnsFileCache(std::string& rCache)
{
    NSUserDefaults* p_default = [NSUserDefaults standardUserDefaults];
    NSString* p_ns_str = [p_default stringForKey:@"DNS_CACHE"];
    if (p_ns_str != nil) {
        rCache = [p_ns_str UTF8String];
    }
}

} // namespace fuze
