//
//  Resource.h
//  FuzeTransport
//
//  Created by Tim Na on 2/26/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef FuzeTransport_Resource_h
#define FuzeTransport_Resource_h

namespace fuze {

class Resource
{
public:
    Resource(int ID) : id_(ID), status_(IDLE)
    {
    }

    inline virtual ~Resource()
    {
    }
    
    enum Status { IDLE, ACTIVE, ZOMBIE };
    
    enum Type
    {
        BASE = 0,     CONNECTION,      SERVERCORE,
        TCP_LISTENER, TCP_TRANSCEIVER,
        UDP_TRANSCEIVER, DTLS_TRANSCEIVER,
        MAX_NUM
    };
    
    void SetZombie() { status_ = ZOMBIE; }
    bool IsActive()  { return (status_ == ACTIVE); }
    int  ID()        { return id_; }
    
    Type ResourceType() { return type_; }
    
    const char* GetStatusString() const;
    const char* GetTypeString() const;

protected:
    // Interface to re-initialize the Resource
    virtual void Reset() = 0;
    
private:
    const int  id_;
    Status     status_;
    Type       type_;
    
    friend class ResourceMgr;
    friend class TransportImpl;
};
    
} // namespace fuze

#endif
