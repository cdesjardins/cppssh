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

class CppsshChannel
{
public:
    CppsshChannel(const std::shared_ptr<CppsshSession>& session);
    bool open(uint32_t channelID);
    bool isConnected();
    bool getShell();
    bool handleReceived(Botan::secure_vector<Botan::byte>& buf);
    bool read(CppsshMessage* data);

private:
    bool doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& request);
    bool handleChannelConfirm(const Botan::secure_vector<Botan::byte>& buf);
    void handleDisconnect(const CppsshConstPacket& packet);
    void handleChannelData(const Botan::secure_vector<Botan::byte>& buf, bool isBanner);
    void handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf);

    std::shared_ptr<CppsshSession> _session;
    uint32_t _windowRecv;
    uint32_t _windowSend;
    bool _channelOpened;
    std::mutex _messageMutex;
    std::queue<CppsshMessage> _messages;
};

#endif

