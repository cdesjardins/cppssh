/*
    cppssh - C++ ssh library
    Copyright (C) 2015  Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
