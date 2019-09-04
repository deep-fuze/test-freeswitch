//
//  TcpTxrxState.h
//  FuzeTransport
//
//  Created by Tim Na on 2/13/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__TcpTxrxState__
#define __FuzeTransport__TcpTxrxState__

#include <Transport.h>

//
// State Machines for handling various TcpTransceiver state
//
// The main purpose of the state machines is to support
// different setup, framing data on top of TCP.
// There are two type of state machines; Setup and Final.
//
// Setup state machine is used to capture the expected
// transaction between two network nodes. For example,
// if client is sending HTTP CONNECT to system proxy,
// we would expect 200 OK or failiure response from it.
// StateSetupOverHttp state machine handles such scenario.
//
// The advantage of having multiple state machine is that
// we can better handle error scenario and also support
// complex cases in managable way.
//
namespace fuze {
    
class TcpTransceiver;

class TcpTxrxState
{
public:
    enum Type
    {
        // final state machines
        TCP,            // Normal TCP
        TLS,            // Normal TLS
        UDP_OVER_TCP,   // If UDP is blocked, TCP is used
        DATA_OVER_TLS,  // Skip encryption/decryption
                        // used for UDP/TCP application
        // setup state machines
        SETUP_TCP,      // Normal Setup TCP
        SETUP_TCP_443,  // using port 443 instead
        SETUP_MAP_TLS,  // Mapping over TLS
        SETUP_TLS,      // perform TLS handshake
        SETUP_HTTP,     // HTTP CONNECT
        SETUP_HTTP_TLS  // HTTP CONNECT + TLS
    };

    virtual Type GetType() const = 0;
    
    virtual void     OnConnected(TcpTransceiver* p) = 0;
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf) = 0;
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf) = 0;
    
    inline virtual ~TcpTxrxState()
    {
    }
};

const char* toStr(TcpTxrxState::Type type);
bool is_setup_state(TcpTxrxState::Type type);
    
//
// StateDefault represent normal TCP connection
//
// It will be set only when application requested
// TCP connection and already has some its own
// own framing header to know where each steam starts
// and ends.
//
class StateTcp : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();

    virtual Type GetType() const { return TCP; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};

class StateSetupTcp : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return SETUP_TCP; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};
    
//
// StateUdpOverTcp will use Fuze Transport Data
// message to transmit the UDP data to the far end.
// This final state machine will result only when
// application requested UDP yet TCP is used to
// establish the connection to far end
//
class StateUdpOverTcp : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return UDP_OVER_TCP; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};
    
//
// StateSetupTcpPort443 is setup state machine
// it handles the session establishment
// with far end Fuze Transport Server component which is
// invoked only when native UDP/TCP is blocked (such as
// certain ports are blocked by firewall) If the mapping
// request is not understood by far end, we can assume
// far end is not a fuze transport.
//
class StateSetupTcpPort443 : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();

    virtual Type GetType() const { return SETUP_TCP_443; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};

//
// StateSetupTls will setup TLS connection to far end
//
class StateSetupTls : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return SETUP_TLS; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};

//
// StateSetupMapTls will try to map connection over TLS
//
class StateSetupMapTls : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return SETUP_MAP_TLS; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};
    
//
// StateDataOverTls will be used once far end is also
// same Fuze Transport and will skip actual encryption/ decryption
// but using TLS header to fool network nodes in between
//
class StateDataOverTls : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return DATA_OVER_TLS; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};

//
// StateTls provides actual TLS connection
//
class StateTls : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return TLS; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};

class StateHttpTls : public TcpTxrxState
{
public:
    static TcpTxrxState* GetInstance();
    
    virtual Type GetType() const { return SETUP_HTTP_TLS; }
    
    virtual void     OnConnected(TcpTransceiver* p);
    virtual uint32_t OnDataReceived(TcpTransceiver* p,
                                    Buffer::Ptr     spBuf);
    virtual void     Send(TcpTransceiver* p,
                          Buffer::Ptr     spBuf);
};
    
    
} // namespace fuze

#endif /* defined(__FuzeTransport__TcpTxrxState__) */
