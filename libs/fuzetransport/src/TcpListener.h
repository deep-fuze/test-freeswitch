//
//  TcpListener.h
//  FuzeTransport
//
//  Created by Tim Na on 11/25/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TcpListener__
#define __FuzeTransport__TcpListener__

#include <Transceiver.h>

namespace fuze {

class TcpListener : public Transceiver
{
public:
    explicit TcpListener(int transID);
    
    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual void SetConnectionID(int connID);
    virtual ConnectionType ConnType();

    // Implement Resource Interface
    virtual void Reset();
    
    // Tcp Listener interface
    void HandleAccept(evutil_socket_t sock, short what);
    
private:
    int              connID_; // connection id that this belongs to
    ConnectionImpl*  pConn_;
    evutil_socket_t  socket_;
    event*           pReadEvent_;
};

} // namespace fuze

#endif /* defined(__FuzeTransport__TcpListener__) */
