/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _SUBCHANNEL_Hxx
#define _SUBCHANNEL_Hxx

#include "packet.h"
#include "transport.h"
#include "threadsafequeue.h"
#include <memory>

class CppsshSubChannel
{
public:
    CppsshSubChannel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName);
    CppsshSubChannel() = delete;
    CppsshSubChannel(const CppsshSubChannel&) = delete;

    virtual ~CppsshSubChannel()
    {
    }

    virtual bool startChannel()
    {
        return true;
    }

    void reduceWindowRecv(uint32_t bytes)
    {
        _windowRecv -= bytes;
    }

    void increaseWindowSend(uint32_t bytes)
    {
        _windowSend += bytes;
    }

    uint32_t getWindowRecv() const
    {
        return _windowRecv;
    }

    const std::string& getChannelName() const
    {
        return _channelName;
    }

    uint32_t getTxChannel() const
    {
        return _txChannel;
    }

    virtual bool doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& request, bool wantReply = true);
    virtual void handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf);
    virtual void handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf);
    virtual bool handleChannelConfirm();
    void handleChannelRequest(const Botan::secure_vector<Botan::byte>& buf);
    virtual void handleEof();
    virtual void handleClose();
    void sendAdjustWindow();
    bool flushOutgoingChannelData();
    bool writeChannel(const uint8_t* data, uint32_t bytes);
    bool readChannel(CppsshMessage* data);
    bool windowChange(const uint32_t cols, const uint32_t rows);
    void setParameters(uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket);
    void handleBanner(const std::shared_ptr<CppsshMessage>& banner);
    static uint32_t getRxWindowSize();

protected:
    ThreadSafeQueue<std::shared_ptr<Botan::secure_vector<Botan::byte> > > _outgoingChannelData;
    ThreadSafeQueue<std::shared_ptr<CppsshMessage> > _incomingChannelData;
    ThreadSafeQueue<Botan::secure_vector<Botan::byte> > _incomingControlData;

    std::shared_ptr<CppsshSession> _session;
    uint32_t _windowRecv;
    uint32_t _windowSend;
    uint32_t _txChannel;
    uint32_t _maxPacket;
    std::string _channelName;
};
#endif
