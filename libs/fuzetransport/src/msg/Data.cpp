//
//  Data.cpp
//  FuzeTransport
//
//  Created by Tim Na on 1/22/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <Data.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, "Data::" << __FUZE_FUNC__ << ": " << B)

#ifdef __linux__
#include <string.h>    // memcpy
#include <arpa/inet.h> // ntohs
#elif defined(WIN32)
#include <WinSock2.h>
#endif

namespace fuze {
    
Data::Data()
{
}

Buffer::Ptr Data::GetHeader()
{
    return spHeader_;
}
    
Buffer::Ptr Data::GetData()
{
    return spData_;
}
    
void Data::SetReceivedData(Buffer::Ptr spBuf)
{
    spData_.reset(new NetworkBuffer(spBuf));
    spData_->setDebugInfo(__FILE__, __LINE__);
    spData_->pull(FUZE_HEADER_SIZE);
}

void Data::SetDataToSend(Buffer::Ptr spBuf)
{
    spData_ = spBuf;

    // if no data is set then create empty data
    if (!spData_) {
        spData_ = Buffer::MAKE(1);
        spData_->setSize(0);
    }

    uint16_t data_len = spData_->size();
    uint16_t len = htons(data_len);    
    
    uint8_t* p_buf = CreateHeader(FUZE_HEADER_SIZE);
    p_buf[0] = FUZE_MARK;
    memcpy(p_buf+1, &len, sizeof(uint16_t));
}

uint8_t* Data::CreateHeader(uint32_t headRoom)
{
    spHeader_ = Buffer::MAKE(headRoom);
    return spHeader_->getBuf();
}
    
TlsAppData::TlsAppData()
{
}

void TlsAppData::SetReceivedData(Buffer::Ptr spBuf)
{
    spData_.reset(new NetworkBuffer(spBuf));
    spData_->setDebugInfo(__FILE__, __LINE__);
    spData_->pull(TLS_HEADER_SIZE);
}

void TlsAppData::SetDataToSend(Buffer::Ptr spBuf)
{
    spData_ = spBuf;

    // if no data is set then create empty data
    if (!spData_) {
        spData_ = Buffer::MAKE(1);
        spData_->setSize(0);
    }
    
    // we expect payload to be there as we created Data
    uint16_t data_len = (uint16_t)spData_->size();
    uint16_t len = htons(data_len);

    uint8_t* p_buf = CreateHeader(TLS_HEADER_SIZE);
    p_buf[0] = 0x17; // TLS application
    p_buf[1] = 3;    // version 3.1
    p_buf[2] = 1;
    memcpy(p_buf+3, &len, sizeof(uint16_t));
}
    
} // namespace fuze
