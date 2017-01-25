//
//  TransportEvent.cpp
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/10/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#include <string.h>
#include <TransportEvent.h>
#include "ConnectionImpl.h"

namespace fuze {


TransportEvent::TransportEvent()
{
#ifdef COPY_TO_BUFFER
  len = 0;
#endif
}

const char* TransportEvent::TETypeStr()
{
    switch (TEType())
    {
        case TE_DATA:       return "DATA";
        case TE_CONN_EVENT: return "CONN_EVENT";
        case TE_NEW_CONN:   return "NEW_CONN";
        default:            return "NONE";
    }
}
    
Buffer::Ptr TransportEvent::Data(string& IP, uint16_t& port, bool& remoteChanged)
{
    return Buffer::Ptr((Buffer*)NULL);
}
    
EventType TransportEvent::EvType()
{
    return ET_NONE;
}
    
Connection::Ptr TransportEvent::Conn()
{
    Connection::Ptr sp_con;
    return sp_con;
}

Buffer::Ptr TEData::Data(string& IP, uint16_t& port, bool& remoteChanged)
{
    NetworkBuffer *nwBuf = dynamic_cast<NetworkBuffer *>(data_.get());
    if (nwBuf) {
        remoteChanged = nwBuf->changed_;
        IP   = nwBuf->remoteIP_;
        port = nwBuf->remotePort_;
    }
    
    return data_;
}
    
} // namespace fuze
