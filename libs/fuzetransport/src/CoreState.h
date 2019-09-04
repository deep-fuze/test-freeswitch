//
//  CoreState.h
//  FuzeTransport
//
//  Created by Tim Na on 2/26/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__CoreState__
#define __FuzeTransport__CoreState__

#include <Transport.h>

namespace fuze {

class ServerCore;
    
class CoreState
{
public:
    enum Type { INITIAL, ACCEPT_TLS, ACCEPTED_TLS, FAILED };
    
    virtual Type GetType() const = 0;
    
    virtual uint32_t OnDataReceived(ServerCore* p,
                                    Buffer::Ptr spBuf) = 0;
    inline virtual ~CoreState()
    {
    }
};

const char* toStr(CoreState::Type type);
    
class StateInitial : public CoreState
{
public:
    static CoreState* GetInstance();
    
    virtual Type GetType() const { return INITIAL; }
    
    virtual uint32_t OnDataReceived(ServerCore* p,
                                    Buffer::Ptr spBuf);
};
    
class StateAcceptTls : public CoreState
{
public:
    static CoreState* GetInstance();
    
    virtual Type GetType() const { return ACCEPT_TLS; }
    
    virtual uint32_t OnDataReceived(ServerCore* p,
                                    Buffer::Ptr spBuf);
};

class StateAcceptedTls : public CoreState
{
public:
    static CoreState* GetInstance();
    
    virtual Type GetType() const { return ACCEPTED_TLS; }
    
    virtual uint32_t OnDataReceived(ServerCore* p,
                                    Buffer::Ptr spBuf);
};
    
class StateFailed : public CoreState
{
public:
    static CoreState* GetInstance();
    
    virtual Type GetType() const { return FAILED; }
    
    virtual uint32_t OnDataReceived(ServerCore* p,
                                    Buffer::Ptr spBuf);
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__CoreState__) */

