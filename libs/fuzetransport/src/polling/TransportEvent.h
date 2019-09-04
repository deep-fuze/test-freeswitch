//
//  TransportEvent.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/10/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __TRANSPORT_EVENT_H__
#define __TRANSPORT_EVENT_H__

#include <Transport.h>
#include <event2/event.h>

namespace fuze {

class TransportEvent
{
public:
    
    typedef fuze_shared_ptr<TransportEvent> Ptr;
    
    enum Type
    {
        TE_DATA,
        TE_CONN_EVENT,
        TE_NEW_CONN
    };
        
    virtual Type             TEType() = 0;
    virtual const char*      TETypeStr();
    virtual Buffer::Ptr      Data(string& IP, uint16_t& port, bool& remoteChanged);
    virtual EventType        EvType();
    virtual Connection::Ptr  Conn();
        
public:
    TransportEvent();

    inline virtual ~TransportEvent()
    {
    }
};
    
class TEData : public TransportEvent
{
private:
    Buffer::Ptr data_;
    
public:
    TEData() {}
    TEData(Buffer::Ptr pData) : data_(pData) {}

    inline virtual Type TEType() { return TE_DATA; }
    Buffer::Ptr Data(string& IP, uint16_t& port, bool& remoteChanged);
};
    
class TEConnEvent : public TransportEvent
{
private:
    EventType type_;
        
public:
    TEConnEvent(EventType pType) : type_(pType) {}

    inline virtual Type TEType() { return TE_CONN_EVENT; }
    inline virtual EventType EvType() { return type_; }
};
    
class TENewConn : public TransportEvent
{
private:
    Connection::Ptr conn_;
        
public:
    TENewConn() : conn_(Connection::Ptr((Connection *) NULL)) {}

    inline Type TEType() { return TE_NEW_CONN; }
    inline virtual Connection::Ptr Conn() { return conn_;}
};
    
}

#endif