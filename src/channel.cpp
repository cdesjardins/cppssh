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
#include "impl.h"
#include "channel.h"
#include "messages.h"
#include "transport.h"
#include "packet.h"
#include "logger.h"
#include <sstream>
#include <iterator>
#include <iomanip>

#define CPPSSH_RX_WINDOW_SIZE (CPPSSH_MAX_PACKET_LEN * 150)

CppsshChannel::CppsshChannel(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _windowRecv(CPPSSH_RX_WINDOW_SIZE),
    _windowSend(0),
    _channelOpened(false)
{
}

bool CppsshChannel::open(uint32_t channelID)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    _windowSend = 0;
    _windowRecv = CPPSSH_RX_WINDOW_SIZE;

    packet.addByte(SSH2_MSG_CHANNEL_OPEN);
    packet.addString("session");
    packet.addInt(channelID);

    packet.addInt(_windowRecv);
    packet.addInt(CPPSSH_MAX_PACKET_LEN);

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
            packet.skipHeader();
            packet.getInt();
            packet.getString(&err);
            _session->_logger->pushMessage(err);
            disconnect();
        }
    }
}

void CppsshChannel::disconnect()
{
    _channelOpened = false;
}

bool CppsshChannel::isConnected()
{
    return _channelOpened;
}

void CppsshChannel::handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf, bool isBanner)
{
    CppsshConstPacket packet(&buf);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    if (isBanner == false)
    {
        packet.getChannelData(message.get());
    }
    else
    {
        packet.getBannerData(message.get());
    }

    _windowRecv -= message->length();
    if (_windowRecv < (CPPSSH_RX_WINDOW_SIZE / 2))
    {
        sendAdjustWindow();
    }

    std::unique_lock<std::mutex> lock(_incomingMessagesMutex);
    _incomingMessages.push(message);
}

bool CppsshChannel::flushOutgoingChannelData()
{
    bool ret = true;
    while (_outgoingMessages.empty() == false)
    {
        std::shared_ptr<Botan::secure_vector<Botan::byte> > message;
        {// new scope for mutex
            std::unique_lock<std::mutex> lock(_outgoingMessagesMutex);
            message = _outgoingMessages.front();
            _outgoingMessages.pop();
        }

        if ((message->size() > 0) && (_windowSend >= message->size()))
        {
            _windowSend -= message->size();
            Botan::secure_vector<Botan::byte> buf;
            CppsshPacket packet(&buf);
            packet.addByte(SSH2_MSG_CHANNEL_DATA);
            packet.addInt(_session->getSendChannel());
            packet.addInt(message->size());
            packet.addVector(*message);
            ret = _session->_transport->sendPacket(buf);
            if (ret == false)
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    return ret;
}

bool CppsshChannel::read(CppsshMessage* data)
{
    bool ret = false;
    std::unique_lock<std::mutex> lock(_incomingMessagesMutex);
    if (_incomingMessages.empty() == false)
    {
        *data = *_incomingMessages.front();
        _incomingMessages.pop();
        ret = true;
    }
    return ret;
}

bool CppsshChannel::send(const uint8_t* data, uint32_t bytes)
{
    uint32_t totalBytesSent = 0;
    std::shared_ptr<Botan::secure_vector<Botan::byte> > message;
    uint32_t maxPacketSize = _session->getMaxPacket() - 64;
    while (totalBytesSent < bytes)
    {
        uint32_t bytesSent = std::min(bytes, maxPacketSize);
        message.reset(new Botan::secure_vector<Botan::byte>());
        CppsshPacket packet(message.get());
        packet.addRawData(data, bytesSent);
        totalBytesSent += bytesSent;
        std::unique_lock<std::mutex> lock(_outgoingMessagesMutex);
        _outgoingMessages.push(message);
    }
    return (totalBytesSent == bytes);
}

bool CppsshChannel::handleChannelConfirm(const Botan::secure_vector<Botan::byte>& buf)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> tmp(buf);
    const CppsshConstPacket packet(&tmp);
    uint32_t field;

    if (packet.getCommand() == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)
    {
        packet.skipHeader();
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

bool CppsshChannel::runXauth(const char* display, std::string* method, std::string* cookie) const
{
    bool ret = false;
    std::stringstream xauth;
    char tmpname[L_tmpnam];
    std::tmpnam(tmpname);
    xauth << "/usr/bin/xauth list " << display << " 2> /dev/null" << " 1> " << tmpname;
    if (system(xauth.str().c_str()) == 0)
    {
        Botan::secure_vector<Botan::byte> buf;
        CppsshPacket packet(&buf);
        if (packet.addFile(tmpname) == true)
        {
            std::string magic(buf.begin(), buf.end());
            std::istringstream iss(magic);
            std::vector<std::string> cookies;
            std::copy(std::istream_iterator<std::string>(iss),
                      std::istream_iterator<std::string>(),
                      std::back_inserter(cookies));
            if (cookies.size() == 3)
            {
                *method = cookies[1];
                *cookie = cookies[2];
                ret = true;
            }
        }
    }
    remove(tmpname);
    return ret;
}

bool CppsshChannel::getFakeX11Cookie(const int size, std::string* fakeX11Cookie) const
{
    std::vector<Botan::byte> random;
    random.resize(size / 2);
    CppsshImpl::RNG->randomize(random.data(), random.size());
    std::stringstream fake;
    for (std::vector<Botan::byte>::const_iterator it = random.begin(); it != random.end(); it++)
    {
        fake << std::hex << std::setw(2) << std::setfill('0') << (int)*it;
    }
    *fakeX11Cookie = fake.str();
    return true;
}

bool CppsshChannel::getX11()
{
    bool ret = false;
    char* display = getenv("DISPLAY");
    if (display != NULL)
    {
        if ((runXauth(display, &_realX11Method, &_realX11Cookie) == true) &&
            (getFakeX11Cookie(_realX11Cookie.size(), &_fakeX11Cookie) == true))
        {
            Botan::secure_vector<Botan::byte> x11req;
            CppsshPacket x11packet(&x11req);
            x11packet.addByte(0);// single connection
            x11packet.addString(_realX11Method);
            x11packet.addString(_fakeX11Cookie);
            x11packet.addInt(0);
            ret = doChannelRequest("x11-req", x11req);
        }
    }
    return ret;
}

bool CppsshChannel::handleReceived(const Botan::secure_vector<Botan::byte>& buf)
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
        case SSH2_MSG_USERAUTH_PK_OK:
        case SSH2_MSG_SERVICE_ACCEPT:
        case SSH2_MSG_KEXDH_REPLY:
        case SSH2_MSG_NEWKEYS:
        case SSH2_MSG_KEXINIT:
            _session->_transport->handleData(buf);
            break;

        case SSH2_MSG_USERAUTH_BANNER:
            _session->_transport->handleData(buf);
            handleIncomingChannelData(buf, true);
            break;

        case SSH2_MSG_CHANNEL_DATA:
            handleIncomingChannelData(buf, false);
            break;

        case SSH2_MSG_CHANNEL_EXTENDED_DATA:
            //handleExtendedData(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_EXTENDED_DATA: " << cmd);
            break;

        case SSH2_MSG_CHANNEL_EOF:
            //handleEof(newPacket.value());
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_EOF: " << cmd);
            break;

        case SSH2_MSG_CHANNEL_OPEN:
            //handleOpen(buf);
            _session->_logger->pushMessage(std::stringstream() << "Unhandled SSH2_MSG_CHANNEL_OPEN: " << cmd);
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

void CppsshChannel::sendAdjustWindow()
{
    uint32_t len = CPPSSH_RX_WINDOW_SIZE - _windowRecv;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_WINDOW_ADJUST);
    packet.addInt(_session->getSendChannel());
    packet.addInt(len);
    _windowRecv += len;

    _session->_transport->sendPacket(buf);
}

void CppsshChannel::handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    // channel number
    packet.getInt();
    // add bytes to the window
    uint32_t size = packet.getInt();
    _windowSend += size;
}

