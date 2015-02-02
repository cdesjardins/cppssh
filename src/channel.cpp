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

CppsshChannel::CppsshChannel(const std::shared_ptr<CppsshSession>& session, unsigned int timeout)
    : _session(session),
    _channelOpened(false),
    _timeout(timeout)
{
}

bool CppsshChannel::openChannel()
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    if (createNewSubChannel(&_mainChannel) == true)
    {
        packet.addByte(SSH2_MSG_CHANNEL_OPEN);
        packet.addString("session");
        packet.addInt(_mainChannel);

        packet.addInt(CPPSSH_RX_WINDOW_SIZE);
        packet.addInt(CPPSSH_MAX_PACKET_LEN);

        if (_session->_transport->sendPacket(buf) == true)
        {
            _channelOpened = _channels.at(_mainChannel)->handleChannelConfirm();
        }
    }
    return _channelOpened;
}

bool CppsshChannel::readMainChannel(CppsshMessage* data)
{
    return _channels.at(_mainChannel)->readChannel(data);
}

bool CppsshChannel::writeMainChannel(const uint8_t* data, uint32_t bytes)
{
    return _channels.at(_mainChannel)->writeChannel(data, bytes);
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

void CppsshSubChannel::handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    uint32_t rxChannel;
    packet.skipHeader();
    rxChannel = packet.getInt();
    packet.getChannelData(message.get());
    _windowRecv -= message->length();
    if (_windowRecv < (CPPSSH_RX_WINDOW_SIZE / 2))
    {
        sendAdjustWindow();
    }

    _incomingChannelData.enqueue(message);
}

void CppsshSubChannel::handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf)
{
    _incomingControlData.enqueue(buf);
}

bool CppsshChannel::createNewSubChannel(uint32_t* rxChannel)
{
    bool ret = false;

    std::shared_ptr<CppsshSubChannel> channel(new CppsshSubChannel(_session, _timeout));

    for (*rxChannel = 1; *rxChannel < 2048; *rxChannel++)
    {
        if (_channels.find(*rxChannel) == _channels.end())
        {
            _channels.insert(std::pair<int, std::shared_ptr<CppsshSubChannel> >(*rxChannel, channel));
            ret = true;
            break;
        }
    }
    return ret;
}

void CppsshSubChannel::sendOpenConfirmation(uint32_t rxChannel)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket openConfirmation(&buf);
    openConfirmation.addByte(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
    openConfirmation.addInt(rxChannel);
    openConfirmation.addInt(_txChannel);
    openConfirmation.addInt(_windowRecv);
    openConfirmation.addInt(CPPSSH_MAX_PACKET_LEN);
}

void CppsshChannel::sendOpenFailure(uint32_t rxChannel, CppsshOpenFailureReason reason)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket openFaulure(&buf);
    openFaulure.addByte(SSH2_MSG_CHANNEL_OPEN_FAILURE);
    openFaulure.addInt(reason);
    openFaulure.addString("Bad request");
    openFaulure.addString("EN");
    _session->_transport->sendPacket(buf);
}

void CppsshChannel::handleOpen(const Botan::secure_vector<Botan::byte>& buf)
{
    /*
    std::string channelName;
    std::string originatorAddr;
    CppsshConstPacket openPacket(&buf);
    openPacket.skipHeader();
    openPacket.getString(&channelName);
    uint32_t txChannel = openPacket.getInt();
    uint32_t windowSize = openPacket.getInt();
    uint32_t maxPacket = openPacket.getInt();
    openPacket.getString(&originatorAddr);
    uint32_t originatorPort = openPacket.getInt();
    if (channelName == "x11")
    {
        uint32_t rxChannel;
        if (createNewRxChannel(windowSize, txChannel, maxPacket, &rxChannel) == true)
        {
            if (connectToX11() == true)
            {
                sendOpenConfirmation(rxChannel);
            }
        }
        else
        {
            sendOpenFailure(txChannel, SSH2_OPEN_RESOURCE_SHORTAGE);
        }
    }
    else
    {
        sendOpenFailure(txChannel, SSH2_OPEN_UNKNOWN_CHANNEL_TYPE);
    }
    */
}

bool CppsshChannel::flushOutgoingChannelData()
{
    bool ret = true;
    std::shared_ptr<std::unique_lock<std::mutex> > lock = _channels.getLock();
    std::map<int, std::shared_ptr<CppsshSubChannel> >::iterator it;
    for (it = _channels.begin(); (it != _channels.end() && (ret == true)); it++)
    {
        ret = it->second->flushOutgoingChannelData();
    }
    return ret;
}

bool CppsshSubChannel::flushOutgoingChannelData()
{
    bool ret = true;
    while (_outgoingChannelData.size() > 0)
    {
        std::shared_ptr<Botan::secure_vector<Botan::byte> > message;
        _outgoingChannelData.dequeue(&message);

        if (message->size() > 0)
        {
            _windowSend -= message->size();
            Botan::secure_vector<Botan::byte> buf;
            CppsshPacket packet(&buf);
            packet.addByte(SSH2_MSG_CHANNEL_DATA);
            packet.addInt(_txChannel);
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

bool CppsshSubChannel::readChannel(CppsshMessage* data)
{
    std::shared_ptr<CppsshMessage> m;
    bool ret = _incomingChannelData.dequeue(&m);
    if (ret == true)
    {
        *data = *m;
    }
    return ret;
}

bool CppsshSubChannel::writeChannel(const uint8_t* data, uint32_t bytes)
{
    uint32_t totalBytesSent = 0;
    std::shared_ptr<Botan::secure_vector<Botan::byte> > message;
    uint32_t maxPacketSize = _maxPacket - 64;
    while (totalBytesSent < bytes)
    {
        uint32_t bytesSent = std::min(bytes, maxPacketSize);
        message.reset(new Botan::secure_vector<Botan::byte>());
        CppsshPacket packet(message.get());
        packet.addRawData(data, bytesSent);
        totalBytesSent += bytesSent;
        _outgoingChannelData.enqueue(message);
    }
    return (totalBytesSent == bytes);
}

bool CppsshSubChannel::handleChannelConfirm()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    if (_incomingControlData.dequeue(&buf, _timeout) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "New channel: " << /* channelId << FIXME: rx channel id */" could not be open. ");
    }
    else
    {
        const CppsshConstPacket packet(&buf);

        if (packet.getCommand() == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)
        {
            packet.skipHeader();
            // Receive Channel
            //uint32_t rxChannel = packet.getInt();
            packet.getInt();
            _txChannel = packet.getInt();
            _windowSend = packet.getInt();
            _maxPacket = packet.getInt();
            ret = true;
        }
    }
    return ret;
}

bool CppsshSubChannel::doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& reqdata)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_txChannel);
    packet.addString(req);
    packet.addByte(1);// want reply == true
    packet.addVector(reqdata);

    if ((_session->_transport->sendPacket(buf) == true) &&
        (_incomingControlData.dequeue(&buf, _timeout) == true) &&
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

    if (_channels.at(_mainChannel)->doChannelRequest("pty-req", buf) == true)
    {
        buf.clear();
        if (_channels.at(_mainChannel)->doChannelRequest("shell", buf) == true)
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
    xauth << "/bin/xauth list " << display << " 2> /dev/null" << " 1> " << tmpname;
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
        if (runXauth(display, &_X11Method, &_realX11Cookie) == false)
        {
            getFakeX11Cookie(16, &_fakeX11Cookie);
            _realX11Cookie = _fakeX11Cookie;
            _X11Method = "MIT-MAGIC-COOKIE-1";
        }
        else
        {
            getFakeX11Cookie(_realX11Cookie.size(), &_fakeX11Cookie);
        }
        Botan::secure_vector<Botan::byte> x11req;
        CppsshPacket x11packet(&x11req);
        x11packet.addByte(0);// single connection
        x11packet.addString(_X11Method);
        x11packet.addString(_fakeX11Cookie);
        x11packet.addInt(0);
        // FIXME: 
        //ret = doChannelRequest("x11-req", x11req);
    }
    return ret;
}

void CppsshChannel::handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    _channels.at(rxChannel)->handleIncomingChannelData(buf);
}

void CppsshChannel::handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    _channels.at(rxChannel)->handleIncomingControlData(buf);
}

void CppsshChannel::handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    uint32_t size = packet.getInt();
    _channels.at(rxChannel)->increaseWindowSend(size);
}

void CppsshChannel::handleIncomingGlobalData(const Botan::secure_vector<Botan::byte>& buf)
{
    _incomingGlobalData.enqueue(buf);
}

bool CppsshChannel::waitForGlobalMessage(Botan::secure_vector<Botan::byte>* buf)
{
    return _incomingGlobalData.dequeue(buf, _timeout);
}

void CppsshChannel::handleBanner(const Botan::secure_vector<Botan::byte>& buf)
{
    const CppsshConstPacket packet(&buf);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    packet.getBannerData(message.get());
    // FIXME: enqueue the banner to mainChannel incomingChannelData
}

void CppsshChannel::handleReceived(const Botan::secure_vector<Botan::byte>& buf)
{
    const CppsshConstPacket packet(&buf);
    Botan::byte cmd = packet.getCommand();
    switch (cmd)
    {
        case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
            handleWindowAdjust(buf);
            break;

        case SSH2_MSG_CHANNEL_SUCCESS:
        case SSH2_MSG_CHANNEL_FAILURE:
        case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
        case SSH2_MSG_CHANNEL_OPEN_FAILURE:
            handleIncomingControlData(buf);
            break;

        case SSH2_MSG_CHANNEL_DATA:
            handleIncomingChannelData(buf);
            break;

        case SSH2_MSG_USERAUTH_FAILURE:
        case SSH2_MSG_USERAUTH_SUCCESS:
        case SSH2_MSG_USERAUTH_PK_OK:
        case SSH2_MSG_SERVICE_ACCEPT:
        case SSH2_MSG_KEXDH_REPLY:
        case SSH2_MSG_NEWKEYS:
        case SSH2_MSG_KEXINIT:
            handleIncomingGlobalData(buf);
            break;
        case SSH2_MSG_USERAUTH_BANNER:
            handleIncomingGlobalData(buf);
            handleBanner(buf);
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
            handleOpen(buf);
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
}

void CppsshSubChannel::sendAdjustWindow()
{
    uint32_t len = CPPSSH_RX_WINDOW_SIZE - _windowRecv;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_WINDOW_ADJUST);
    packet.addInt(_txChannel);
    packet.addInt(len);
    _windowRecv += len;
    _session->_transport->sendPacket(buf);
}

CppsshSubChannel::CppsshSubChannel(const std::shared_ptr<CppsshSession>& session, unsigned int timeout)
    : _session(session),
    _windowRecv(CPPSSH_RX_WINDOW_SIZE),
    _windowSend(0),
    _txChannel(0),
    _maxPacket(0),
    _timeout(timeout)
{
}

