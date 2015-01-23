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
#include "channel.h"
#include "messages.h"
#include "transport.h"
#include "packet.h"
#include "logger.h"
#include <sstream>

CppsshChannel::CppsshChannel(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _windowRecv(0),
    _windowSend(0),
    _channelOpened(false)
{
}

bool CppsshChannel::open(uint32_t channelID)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    _windowSend = 0;
    _windowRecv = MAX_PACKET_LEN - 2400;

    packet.addByte(SSH2_MSG_CHANNEL_OPEN);
    packet.addString("session");
    packet.addInt(channelID);

    packet.addInt(_windowRecv);
    packet.addInt(MAX_PACKET_LEN);

    if (_session->_transport->sendPacket(buf) == true)
    {
        if (_session->_transport->waitForPacket(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &packet) <= 0)
        {
            std::string err;
            if (packet.size() > 0)
            {
                CppsshPacket message(&buf);
                Botan::secure_vector<Botan::byte> payload(Botan::secure_vector<Botan::byte>(message.getPayloadBegin() + 1, message.getPayloadEnd()));
                CppsshPacket payloadPacket(&payload);
                payloadPacket.getInt();
                payloadPacket.getString(err);
            }
            _session->_logger->pushMessage(std::stringstream() << "New channel: " << channelID << " could not be open. " << err);
        }
        else
        {
            _channelOpened = handleChannelConfirm(buf);
        }
    }
    return _channelOpened;
}

bool CppsshChannel::handleChannelConfirm(const Botan::secure_vector<Botan::byte>& buf)
{
    Botan::secure_vector<Botan::byte> tmp(buf.begin() + 1, buf.end() - 1);
    CppsshPacket packet(&tmp);
    uint32_t field;

    // Receive Channel
    packet.getInt();
    // Send Channel
    field = packet.getInt();
    _session->setSendChannel(field);

    // Window Size
    field = packet.getInt();
    _windowSend = field;

    // Max Packet
    field = packet.getInt();
    _session->setMaxPacket(field);
    return true;
}

void CppsshChannel::getShell()
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addByte(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString("pty-req");
    packet.addByte(0);
    packet.addString("dumb");
    packet.addInt(80);
    packet.addInt(24);
    packet.addInt(0);
    packet.addInt(0);
    packet.addString("");
    if (_session->_transport->sendPacket(buf) == true)
    {
        buf.clear();
        packet.addByte(SSH2_MSG_CHANNEL_REQUEST);
        packet.addInt(_session->getSendChannel());
        packet.addString("shell");
        packet.addByte(0);
        _session->_transport->sendPacket(buf);
    }
}

