//
//  Transceiver.h
//  FuzeTransport
//
//  Created by Tim Na on 11/20/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef FuzeTransport_Transceiver_h
#define FuzeTransport_Transceiver_h

#include <TransportImpl.h>
#include <Resource.h>

namespace fuze {

//
// Transceiver has strong association with
// ConnectionImpl as it shared business logic
// The purpose is to hide the actual transport
// usage on ConnectionImpl
//
class Transceiver : public NotCopyable
                  , public Resource
{
public:
    virtual bool Start() = 0;
    virtual bool Send(Buffer::Ptr spBuffer)  = 0;
    virtual bool Send(const uint8_t* buf, size_t size) = 0;
    virtual void SetConnectionID(int connID) = 0;
    virtual ConnectionType ConnType()  = 0;
    
    explicit Transceiver(int ID) : Resource(ID), flowID_(0) {}

protected:
    unsigned long flowID_; // for qWave
};

} // namespace fuze
    
#endif
