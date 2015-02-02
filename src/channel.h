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
#ifndef _CHANNEL_Hxx
#define _CHANNEL_Hxx

#include "packet.h"
#include "session.h"
#include "messages.h"
#include "tsmem.h"

class CppsshSubChannel;

class CppsshChannel
{
public:
    CppsshChannel(const std::shared_ptr<CppsshSession>& session, unsigned int timeout);
    bool openChannel();
    bool readMainChannel(CppsshMessage* data);
    bool writeMainChannel(const uint8_t* data, uint32_t bytes);
    bool isConnected();
    bool getShell();
    bool getX11();
    void handleReceived(const Botan::secure_vector<Botan::byte>& buf);
    bool flushOutgoingChannelData();
    void disconnect();
    bool waitForGlobalMessage(Botan::secure_vector<Botan::byte>* buf);

private:
    void handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf);
    void handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf);
    void handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf);
    void handleIncomingGlobalData(const Botan::secure_vector<Botan::byte>& buf);
    void handleBanner(const Botan::secure_vector<Botan::byte>& buf);

    void handleDisconnect(const CppsshConstPacket& packet);
    void handleOpen(const Botan::secure_vector<Botan::byte>& buf);
    bool runXauth(const char* display, std::string* method, std::string* cookie) const;
    bool getFakeX11Cookie(const int size, std::string* fakeX11Cookie) const;
    bool createNewSubChannel(const std::string& channelName, uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket, uint32_t* rxChannel);
    bool createNewSubChannel(const std::string& channelName, uint32_t* rxChannel);
    void sendOpenFailure(uint32_t txChannel, CppsshOpenFailureReason reason);

    std::shared_ptr<CppsshSession> _session;
    bool _channelOpened;
    std::string _X11Method;
    std::string _realX11Cookie;
    std::string _fakeX11Cookie;

    CppsshTsQueue<Botan::secure_vector<Botan::byte> > _incomingGlobalData;
    CppsshTsMap<int, std::shared_ptr<CppsshSubChannel> > _channels;
    unsigned int _timeout;
    uint32_t _mainChannel;
};

class CppsshSubChannel
{
public:
    CppsshSubChannel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName, unsigned int timeout);
    ~CppsshSubChannel()
    {
    }

    void reduceWindowRecv(uint32_t bytes)
    {
        _windowRecv -= bytes;
    }

    void increaseWindowSend(uint32_t bytes)
    {
        _windowSend += bytes;
    }

    uint32_t getWindowRecv()
    {
        return _windowRecv;
    }

    bool doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& request);
    void handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf);
    void handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf);
    bool handleChannelConfirm();

    void sendOpenConfirmation(uint32_t rxChannel);

    void sendAdjustWindow();
    bool flushOutgoingChannelData();
    bool readChannel(CppsshMessage* data);
    bool writeChannel(const uint8_t* data, uint32_t bytes);
    void setParameters(uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket);

private:
    CppsshSubChannel();
    CppsshSubChannel(const CppsshSubChannel&);
    CppsshTsQueue<std::shared_ptr<Botan::secure_vector<Botan::byte> > > _outgoingChannelData;
    CppsshTsQueue<std::shared_ptr<CppsshMessage> > _incomingChannelData;
    CppsshTsQueue<Botan::secure_vector<Botan::byte> > _incomingControlData;

    std::shared_ptr<CppsshSession> _session;
    uint32_t _windowRecv;
    uint32_t _windowSend;
    uint32_t _txChannel;
    uint32_t _maxPacket;
    unsigned int _timeout;
    std::string _channelName;
};

#endif

