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

#ifdef WIN32
#include <qos2.h>
#include <fuze/core/win32/DllImport.h>
#endif

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
    
    explicit Transceiver(int ID) :
        Resource(ID)
#ifdef WIN32
        // qWAVE isn't available on Windows Server by default, so we load it
        // dynamically and fail gracefully if it isn't present.
        , pfnQosCreateHandle_(L"qwave.dll", "QOSCreateHandle")
        , pfnQosAddSocketToFlow_(L"qwave.dll", "QOSAddSocketToFlow")
#endif
        {
        }

#ifdef WIN32
protected:
    // qWAVE isn't available on Windows Server by default, so we load it
    // dynamically and fail gracefully if it isn't present.
    typedef BOOL(__stdcall *PFNQOSCreateHandle)(
        _In_    PQOS_VERSION    Version,
        _Out_   PHANDLE         QOSHandle);

    typedef BOOL(__stdcall *PFNQOSAddSocketToFlow)(
        _In_        HANDLE              QOSHandle,
        _In_        SOCKET              Socket,
        _In_opt_    PSOCKADDR           DestAddr,
        _In_        QOS_TRAFFIC_TYPE    TrafficType,
        _In_opt_    DWORD               Flags,
        _Inout_     PQOS_FLOWID         FlowId);

    fuze::core::win32::DllImport<PFNQOSCreateHandle> pfnQosCreateHandle_;
    fuze::core::win32::DllImport<PFNQOSAddSocketToFlow> pfnQosAddSocketToFlow_;
#endif
};

} // namespace fuze
    
#endif
