//
//  DnsFileCacheWin.cpp
//  FuzeTransport
//
//  Created by Tim Na on 9/28/17.
//  Copyright © 2017 Fuze. All rights reserved.
//
#include <string>
#include <Windows.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

using std::string;

class DnsFileCache
{
public:
    static DnsFileCache* GetInstance() 
    {
        static DnsFileCache dns;
        return &dns;
    }

    ~DnsFileCache() 
    {
        if (propertyStoreKey_ != NULL) {
            RegCloseKey(propertyStoreKey_);
        }
    }
    
    bool GetString(const char* pName, string& rOutput)
    {
        DWORD data = 0;
        DWORD type = 0;
        DWORD status = RegGetValueA(propertyStoreKey_, NULL, pName, RRF_RT_REG_SZ, &type, NULL, &data);
        if (status != ERROR_SUCCESS) {
            return false;
        }

        std::unique_ptr<CHAR> temp(new CHAR[data + 1]);

        status = RegGetValueA(propertyStoreKey_, NULL, pName, RRF_RT_REG_SZ, &type, temp.get(), &data);
        if (status != ERROR_SUCCESS) {
            return false;
        }

        // RegGetValue ensures the string is null-terminated.
        rOutput = temp.get();
        return true;        
    }
    

    void SetString(const char* pName, string& rValue)
    {
        RegSetValueExA(
            propertyStoreKey_,
            pName,
            NULL,
            REG_SZ,
            (BYTE*)rValue.c_str(),
            rValue.length()+1); 
    }
    
private:
    DnsFileCache()
        : propertyStoreKey_(NULL)
    {
        LSTATUS status = RegCreateKeyEx(HKEY_CURRENT_USER,
                                        L"Software\\FuzeBox\\PropertyStore",
                                        0,
                                        NULL,
                                        0,
                                        KEY_ALL_ACCESS,
                                        NULL,
                                        &propertyStoreKey_,
                                        NULL);

        if (status != ERROR_SUCCESS) {
            ELOG("unable to open property store key: " << GetLastError());
        }
    }

    HKEY  propertyStoreKey_;
};


void SetDnsFileCache(string cache)
{
    DnsFileCache::GetInstance()->SetString("DnsCache", cache);
}

void GetDnsFileCache(string& rCache)
{
    DnsFileCache::GetInstance()->GetString("DnsCache", rCache);
}

} // namespace fuze
