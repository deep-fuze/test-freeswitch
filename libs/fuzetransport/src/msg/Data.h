//
//  Data.h
//  FuzeTransport
//
//  Created by Tim Na on 1/22/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __FuzeTransport__Data__
#define __FuzeTransport__Data__

#include <Message.h>

namespace fuze {
    
//
// Fuze Data : Used as framing info on sending UDP over TCP
//
// -------------------------------------------------
// |  FUZE HEADER  |     Length (2 bytes)          |
// -------------------------------------------------
// |1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8|
// -------------------------------------------------
//
// - First byte 0xFE (FuzE) indicates that this is Fuze Transport Message
// - Payload Length is given 2 bytes for maximum UDP size
//

class Data
{
public:
    Data();
    inline virtual ~Data() {}
    
    virtual void SetDataToSend(Buffer::Ptr spSend);
    virtual void SetReceivedData(Buffer::Ptr spRecv);

    // retrieve the data
    Buffer::Ptr GetHeader();
    Buffer::Ptr GetData();
    
    void SetAllocator(Connection* pCon);

    static const uint8_t  FUZE_MARK = 0xFE;
    static const uint32_t FUZE_HEADER_SIZE = 3;
    
protected:
    
    uint8_t* CreateHeader(uint32_t headRoom);
    
    Buffer::Ptr spHeader_;
    Buffer::Ptr spData_;
    
    Connection* pAllocator_; // connection as memory allocator
};
    
class TlsAppData : public Data
{
public:
    TlsAppData();
    
    // override following methods from Data
    virtual void SetDataToSend(Buffer::Ptr spSend);
    virtual void SetReceivedData(Buffer::Ptr spRecv);
    
    static const uint32_t TLS_HEADER_SIZE = 5;
};
    
} // namespace fuze

#endif /* defined(__FuzeTransport__Data__) */
