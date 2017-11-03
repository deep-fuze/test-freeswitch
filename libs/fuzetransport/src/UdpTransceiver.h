//
//  UdpTransceiver.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/11/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FUZE_UDP_TRANSCEIVER_H__
#define __FUZE_UDP_TRANSCEIVER_H__

#include <Transceiver.h>

#if defined(__linux__) && !defined(ANDROID)
#include <atomic>
#include <strings.h>
#endif

namespace fuze {

class UdpTransceiver : public Transceiver
{
public:
    explicit UdpTransceiver(int transID);

    // Implement Transceiver Interfaces
    virtual bool Start();
    virtual bool Send(Buffer::Ptr spBuffer);
    virtual bool Send(const uint8_t* buf, size_t size);
    virtual bool Send(const uint8_t* buf, size_t size, const fuze::Address& rRemote);
    virtual void SetConnectionID(int connID);
    virtual ConnectionType ConnType();
    virtual void GetSendQInfo(size_t& rNum, uint32_t& rBufSize);

    // Implement Resource Interface
    virtual void Reset();

protected:

    bool CreateLibEvent(uint16_t timeout);
    bool HandleRemoteChange(const Address& rRecvAddr);
    bool SendPayload(char* pData, long dataLen, const Address& rRemote);

    // Interface for libevent callback
    static void OnLibEvent(evutil_socket_t sock, short what, void* pArg);
    void OnReadEvent();
    void OnWriteEvent();
    void OnTimeOutEvent();

    static const size_t Q_SIZE = 300;

    int                 connID_;
    ConnectionImpl*     pConn_;

    evutil_socket_t     socket_;

    event*              pReadEvent_;
    event*              pWriteEvent_;

    bool                connectedUdp_;
    string              remoteIP_;
    uint16_t            remotePort_;

    bool                bConnected_;      // flag to track first packet came in

    MutexLock           qlock_;
    queue<Buffer::Ptr>  sendQ_;
    uint32_t            qSize_;
    bool                writeAdded_;

    bool                reservedPort_;    // for NGV, reserving port

    uint32_t            recvBufSize_;

protected: // NAT adopatation logic
    uint64_t            recvCnt_;         // valid stream count
    int64_t             checkTime_;
    uint64_t            lastRecvCnt_;
    uint16_t            remoteChangeCnt_; // counter to monitor remote change
    Address             lastNewRemoteAddr_;

    char                pName_[16];
    uint32_t            dropCnt_;
};

#if defined(__linux__) && !defined(ANDROID)

#define MAX_PACKET_SIZE 1600UL

class BulkUdpTransceiver : public UdpTransceiver,
                           public Timer
{
public:
    explicit BulkUdpTransceiver(int transID) : UdpTransceiver(transID), m_msgPtr(&m_msg1), m_timer(0), m_lastSendTime(0) {}
    virtual ~BulkUdpTransceiver() {stopTimer();}

    virtual bool Start() override;
    virtual void Reset() override;
    virtual bool Send(const uint8_t* buf, size_t size, const fuze::Address& rRemote) override;
    virtual ConnectionType ConnType() override {return CT_BULK_UDP;}

    virtual void OnTimer(int32_t data) override;

private:
    struct MsgData
    {
        struct DataHolder
        {
            void* getDataSlot(size_t idx) {return m_data[idx];}
            Address& getRemoteAddress(size_t idx) {return m_remoteAddresses[idx];}

        private:
            uint8_t m_data[UIO_MAXIOV][MAX_PACKET_SIZE];
            Address m_remoteAddresses[UIO_MAXIOV];
        };

        MsgData() : m_numMsgs(0), m_nextMsgIdx(0)
        {
            bzero(m_msg, sizeof(m_msg));
            bzero(m_cumulativeMsgSize, sizeof(m_cumulativeMsgSize));
        }

        void reset()
        {
            m_numMsgs.store(0);
            m_nextMsgIdx.store(0);
            bzero(m_cumulativeMsgSize, sizeof(m_cumulativeMsgSize));
        }

        mmsghdr m_msg[UIO_MAXIOV];
        iovec m_msgData[UIO_MAXIOV];
        size_t m_cumulativeMsgSize[UIO_MAXIOV];
        DataHolder m_dataHolder;
        std::atomic<unsigned int> m_numMsgs;
        std::atomic<size_t> m_nextMsgIdx;
    };

    MsgData* getAltMsgData(MsgData* current) {return (current == &m_msg1 ? &m_msg2 : &m_msg1);}
    void sendInternal(MsgData* msgPtr);
    void stopTimer();

    static constexpr int32_t BULK_UDP_SEND_DATA_TIMER = 20; // 20 millisec
    static constexpr int32_t BULK_UDP_SEND_DATA_CTX = 1;

    MsgData m_msg1;
    MsgData m_msg2;
    std::atomic<MsgData*> m_msgPtr;
    std::atomic<int64_t> m_timer;
    std::atomic<int64_t> m_lastSendTime;
};
#else
typedef UdpTransceiver BulkUdpTransceiver;
#endif

} // namespace fuze


#endif
