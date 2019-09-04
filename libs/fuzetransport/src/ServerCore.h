//
//  ServerCore.h
//  FuzeTransport
//
//  Created by Tim Na on 1/29/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__ServerCore__
#define __FuzeTransport__ServerCore__

#include <Resource.h>
#include <TcpCore.h>
#include <TlsCore.h>
#include <Message.h>
#include <HTTP.h>
#include <CoreState.h>

#include <memory>

namespace fuze {
    
using std::auto_ptr;
    
// structure that holds binding info of server's listening connection
struct BindingInfo
{
    ConnectionType  type_;
    int             connID_;
    string          ipStr_;
    uint16_t        port_;
    
    BindingInfo();
    
    void Clear();
};
    
//
// concrete class that represents the client that connected to
// our port 443 listening server to bypass firewall issue
//
class ServerCore : public Resource
                 , public TcpCoreUser
                 , public TlsCoreUser
{
public:
    typedef fuze_shared_ptr<ServerCore> Ptr;
    
    ServerCore(int ID);

    // Implement Resource Interface
    virtual void Reset();
    
    // Implement TcpCoreUser Interface
    virtual evutil_socket_t Socket();
    virtual uint32_t OnDataReceived(Buffer::Ptr spBuf);
    virtual void     OnBytesSent(uint32_t bytesSent);
    virtual void     OnBytesRecv(uint32_t bytesRecv);
    virtual void     OnDisconnect();
    virtual void     OnReadError(int error);
    virtual void     OnWriteError(int error);
    virtual void     OnReadTimeout() {} // for client only
    
    // Implement TlsCoreUser Interface
    virtual void OnDataEncrypted(Buffer::Ptr spData);
    virtual void OnDataDecrypted(Buffer::Ptr spData);
    virtual void OnInternalError();
    
    // Set the socket from server
    // note that this won't close the socket
    // as we expect that to happen in Reset
    void SetSocket(evutil_socket_t sock);
        
    // handle Fuze/HTTP/TLS messages
    uint32_t OnHttpMessage(uint8_t* pBuf, uint32_t bufLen);
    
    void SendHttpResponse(uint32_t code, const char* pReason);
    
    // timestamping the start time for guarding against faulty
    // program connecting us at 443
    void    SetStartTime();
    int64_t GetStartTime();
    
private:
    
    void RequestRemove();
    
    evutil_socket_t  socket_;
    TcpCore          tcpCore_;
    
    TlsCore::Ptr     spTlsCore_;
    Buffer::Ptr      recvBuf_; // for incoming TLS message
    
    BindingInfo      bindInfo_; // to store binding info
    
    int64_t          startTime_;
    
private:
    void SetState(CoreState::Type type);
    
    CoreState* pState_;
    
    friend class StateInitial;
    friend class StateAcceptTls;
    friend class StateAcceptedTls;
    friend class StateFailed;
};

} // namespace fuze

#endif /* defined(__FuzeTransport__ServerCore__) */
