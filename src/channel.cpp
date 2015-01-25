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
        if (_session->_transport->waitForPacket(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &packet) == false)
        {
            _session->_logger->pushMessage(std::stringstream() << "New channel: " << channelID << " could not be open. ");
        }
        else
        {
            _channelOpened = handleChannelConfirm(buf);
        }
    }
    return _channelOpened;
}

void CppsshChannel::handleDisconnect(const CppsshConstPacket& packet)
{
    if (packet.size() > 0)
    {
        std::string err;
        if (packet.getCommand() == SSH2_MSG_DISCONNECT)
        {
            Botan::secure_vector<Botan::byte> payload(Botan::secure_vector<Botan::byte>(packet.getPayloadBegin() + 1, packet.getPayloadEnd()));
            CppsshConstPacket payloadPacket(&payload);
            payloadPacket.getInt();
            payloadPacket.getString(err);
            _session->_logger->pushMessage(err);
            _channelOpened = false;
        }
    }
}

bool CppsshChannel::isConnected()
{
    return _channelOpened;
}

void CppsshChannel::handleChannelData(const Botan::secure_vector<Botan::byte>& buf, bool isBanner)
{
    CppsshConstPacket packet(&buf);
    CppsshMessage message;
    if (isBanner == false)
    {
        packet.getChannelData(message);
    }
    else
    {
        packet.getBannerData(message);
    }
    std::unique_lock<std::mutex> lock(_messageMutex);
    _messages.push(message);
}

void CppsshChannel::handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf)
{
}

bool CppsshChannel::read(CppsshMessage* data)
{
    bool ret = false;
    std::unique_lock<std::mutex> lock(_messageMutex);
    if (_messages.empty() == false)
    {
        *data = _messages.front();
        _messages.pop();
        ret = true;
    }
    return ret;
}

bool CppsshChannel::handleChannelConfirm(const Botan::secure_vector<Botan::byte>& buf)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> tmp(buf);
    const CppsshConstPacket packet(&tmp);
    uint32_t field;

    if (packet.getCommand() == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)
    {
        Botan::secure_vector<Botan::byte> payload(packet.getPayloadBegin() + 1, packet.getPayloadEnd());
        //Botan::secure_vector<Botan::byte> payload(buf.begin() + 1, buf.end() - 1);
        const CppsshConstPacket payloadPacket(&payload);

        // Receive Channel
        payloadPacket.getInt();
        // Send Channel
        field = payloadPacket.getInt();
        _session->setSendChannel(field);

        // Window Size
        field = payloadPacket.getInt();
        _windowSend = field;

        // Max Packet
        field = payloadPacket.getInt();
        _session->setMaxPacket(field);
        ret = true;
    }
    return ret;
}

bool CppsshChannel::doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& reqdata)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString(req);
    packet.addByte(1);// want reply == true
    packet.addVector(reqdata);
    if ((_session->_transport->sendPacket(buf) == true) &&
        (_session->_transport->waitForPacket(0, &packet) == true) &&
        (packet.getCommand() == SSH2_MSG_CHANNEL_SUCCESS))
    {
        ret = true;
    }
    else
    {
        _session->_logger->pushMessage(std::stringstream() << "Unable to send channel request: " << req);
    }
    return ret;
}

bool CppsshChannel::getShell()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addString("dumb");
    packet.addInt(80);
    packet.addInt(24);
    packet.addInt(0);
    packet.addInt(0);
    packet.addString("");
    if (doChannelRequest("pty-req", buf) == true)
    {
        buf.clear();
        if (doChannelRequest("shell", buf) == true)
        {
            ret = true;
        }
    }
    return ret;
}

bool CppsshChannel::handleReceived(Botan::secure_vector<Botan::byte>& buf)
{
    const CppsshConstPacket packet(&buf);
    bool ret = false;
    int cmd = packet.getCommand();
    switch (cmd)
    {
        case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
            handleWindowAdjust(buf);
            break;

        case SSH2_MSG_CHANNEL_SUCCESS:
        case SSH2_MSG_CHANNEL_FAILURE:
        case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
        case SSH2_MSG_CHANNEL_OPEN_FAILURE:
        case SSH2_MSG_USERAUTH_FAILURE:
        case SSH2_MSG_USERAUTH_SUCCESS:
        case SSH2_MSG_SERVICE_ACCEPT:
        case SSH2_MSG_KEXDH_REPLY:
        case SSH2_MSG_NEWKEYS:
        case SSH2_MSG_KEXINIT:
            _session->_transport->handleData(buf);
            break;
        case SSH2_MSG_USERAUTH_BANNER:
            _session->_transport->handleData(buf);
            handleChannelData(buf, true);
            break;

        case SSH2_MSG_CHANNEL_DATA:
            handleChannelData(buf, false);
            break;

        case SSH2_MSG_CHANNEL_EXTENDED_DATA:
            //handleExtendedData(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_EXTENDED_DATA: " << cmd);
            break;

        case SSH2_MSG_CHANNEL_EOF:
            //handleEof(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_EOF: " << cmd);
            break;

        case SSH2_MSG_CHANNEL_CLOSE:
            //handleClose(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_CLOSE: " << cmd);
            break;

        case SSH2_MSG_CHANNEL_REQUEST:
            //handleRequest(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_REQUEST: " << cmd);
            break;

        case SSH2_MSG_IGNORE:
            break;

        case SSH2_MSG_DISCONNECT:
            handleDisconnect(packet);
            break;

        default:
            _session->_logger->pushMessage(std::stringstream() << "Unhandled command encountered: " << cmd);
            break;
    }
    return ret;
}

