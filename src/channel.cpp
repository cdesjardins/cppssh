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
    _channelOpened(false),
    _mainChannel(0)
{
}
bool CppsshChannel::establish(const std::string& host, short port)
{
    bool ret = false;
    std::string channelName("session");
    if (createNewSubChannel(channelName, &_mainChannel) == true)
    {
        SOCKET sock;
        ret = _session->_transport->establish(host, port, &sock);
        _channels.at(_mainChannel)->setSock(sock);
    }
    return ret;
}

bool CppsshChannel::openChannel()
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_OPEN);
    packet.addString(_channels.at(_mainChannel)->getChannelName());
    packet.addInt(_mainChannel);

    packet.addInt(CPPSSH_RX_WINDOW_SIZE);
    packet.addInt(CPPSSH_MAX_PACKET_LEN);

    if (_session->_transport->sendMessage(buf, getMainSocket()) == true)
    {
        _channelOpened = _channels.at(_mainChannel)->handleChannelConfirm();
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

SOCKET CppsshChannel::getMainSocket()
{
    return _channels.at(_mainChannel)->getSock();
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

void CppsshChannel::getSockList(std::vector<SOCKET>* socks) const
{
    std::shared_ptr<std::unique_lock<std::mutex> > lock = _channels.getLock();
    std::map<int, std::shared_ptr<CppsshSubChannel> >::const_iterator it;
    for (it = _channels.cbegin(); it != _channels.cend(); it++)
    {
        socks->push_back(it->second->getSock());
    }
}

void CppsshSubChannel::handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    packet.skipHeader();
    // rx channel
    uint32_t rxChannel = packet.getInt();
    packet.getChannelData(message.get());
    _windowRecv -= message->length();
    if (_windowRecv < (CPPSSH_RX_WINDOW_SIZE / 2))
    {
        sendAdjustWindow();
    }
    // FIXME: Once I figure this out, I should make it not suck
    if (rxChannel == 101)
    {
        if (_first == true)
        {
            Botan::secure_vector<Botan::byte> magicVec((Botan::byte*)message->message(), (Botan::byte*)message->message() + message->length());
            CppsshPacket magicPacket(&magicVec);
            magicPacket.replace(message->length() - _session->_channel->_realX11Cookie.size(), _session->_channel->_realX11Cookie);
            _first = false;
        }
        writeChannel(message->message(), message->length());
    }
    else
    {
        _incomingChannelData.enqueue(message);
    }
}

void CppsshSubChannel::handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf)
{
    _incomingControlData.enqueue(buf);
}

bool CppsshChannel::createNewSubChannel(const std::string& channelName, uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket, uint32_t* rxChannel)
{
    bool ret = createNewSubChannel(channelName, rxChannel);
    if (ret == true)
    {
        _channels.at(*rxChannel)->setParameters(windowSend, txChannel, maxPacket);
    }
    return ret;
}

bool CppsshChannel::createNewSubChannel(const std::string& channelName, uint32_t* rxChannel)
{
    int chan;
    bool ret = false;

    std::shared_ptr<CppsshSubChannel> channel(new CppsshSubChannel(_session, channelName));

    for (chan = 100; chan < 2048; chan++)
    {
        if (_channels.find(chan) == _channels.cend())
        {
            _channels.insert(std::pair<int, std::shared_ptr<CppsshSubChannel> >(chan, channel));
            *rxChannel = chan;
            ret = true;
            break;
        }
    }
    return ret;
}

void CppsshSubChannel::setParameters(uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket)
{
    _windowSend = windowSend;
    _txChannel = txChannel;
    _maxPacket = maxPacket;
}

void CppsshChannel::sendOpenConfirmation(uint32_t rxChannel)
{
    std::shared_ptr<CppsshSubChannel> channel = _channels.at(rxChannel);
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket openConfirmation(&buf);
    openConfirmation.addByte(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
    openConfirmation.addInt(channel->getTxChannel());
    openConfirmation.addInt(rxChannel);
    openConfirmation.addInt(channel->getWindowRecv());
    openConfirmation.addInt(CPPSSH_MAX_PACKET_LEN);
    _session->_transport->sendMessage(buf, getMainSocket());
}

void CppsshChannel::sendOpenFailure(uint32_t rxChannel, CppsshOpenFailureReason reason)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket openFaulure(&buf);
    openFaulure.addByte(SSH2_MSG_CHANNEL_OPEN_FAILURE);
    openFaulure.addInt(reason);
    openFaulure.addString("Bad request");
    openFaulure.addString("EN");
    _session->_transport->sendMessage(buf, getMainSocket());
}

void CppsshChannel::handleOpen(const Botan::secure_vector<Botan::byte>& buf)
{
    std::string channelName;
    std::string originatorAddr;
    CppsshConstPacket openPacket(&buf);
    openPacket.skipHeader();
    openPacket.getString(&channelName);
    uint32_t txChannel = openPacket.getInt();
    uint32_t windowSend = openPacket.getInt();
    uint32_t maxPacket = openPacket.getInt();
    openPacket.getString(&originatorAddr);
    //uint32_t originatorPort = openPacket.getInt();
    if (channelName == "x11")
    {
        uint32_t rxChannel;
        if (createNewSubChannel(channelName, windowSend, txChannel, maxPacket, &rxChannel) == true)
        {
            SOCKET sock;
            if (_session->_transport->establishX11(&sock) == true)
            {
                _channels.at(rxChannel)->setSock(sock);
                sendOpenConfirmation(rxChannel);
            }
            else
            {
                sendOpenFailure(txChannel, SSH2_OPEN_CONNECT_FAILED);
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
}

bool CppsshChannel::flushOutgoingChannelData()
{
    bool ret = true;
    std::shared_ptr<std::unique_lock<std::mutex> > lock = _channels.getLock();
    std::map<int, std::shared_ptr<CppsshSubChannel> >::const_iterator it;
    for (it = _channels.cbegin(); (it != _channels.cend() && (ret == true)); it++)
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
            ret = _session->_transport->sendMessage(buf, _sock);
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
    if (_incomingControlData.dequeue(&buf, _session->getTimeout()) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "New channel: " << /* channelId << FIXME: rx channel id */ " could not be open. ");
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

    if ((_session->_transport->sendMessage(buf, _sock) == true) &&
        (_incomingControlData.dequeue(&buf, _session->getTimeout()) == true) &&
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

bool CppsshChannel::runXauth(const char* display, std::string* method, Botan::secure_vector<Botan::byte>* cookie) const
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
                std::string c(cookies[2]);
                for (size_t i = 0; i < c.length(); i += 2)
                {
                    int x;
                    std::istringstream css(c.substr(i, 2));
                    css >> std::hex >> x;
                    cookie->push_back((Botan::byte)x);
                }
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
            _X11Method = "MIT-MAGIC-COOKIE-1";
        }
        else
        {
            getFakeX11Cookie(_realX11Cookie.size(), &_fakeX11Cookie);
        }
        int displayNum;
        int screenNum;

        CppsshTransport::parseDisplay(display, &displayNum, &screenNum);
        Botan::secure_vector<Botan::byte> x11req;
        CppsshPacket x11packet(&x11req);
        x11packet.addByte(0);// single connection
        x11packet.addString(_X11Method);
        x11packet.addString(_fakeX11Cookie);
        x11packet.addInt(screenNum);
        ret = _channels.at(_mainChannel)->doChannelRequest("x11-req", x11req);
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
    //std::cout << "handleWindowAdjust " << rxChannel << " " << size << std::endl;
    _channels.at(rxChannel)->increaseWindowSend(size);
}

void CppsshChannel::handleIncomingGlobalData(const Botan::secure_vector<Botan::byte>& buf)
{
    _incomingGlobalData.enqueue(buf);
}

bool CppsshChannel::waitForGlobalMessage(Botan::secure_vector<Botan::byte>* buf)
{
    return _incomingGlobalData.dequeue(buf, _session->getTimeout());
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
    _session->_transport->sendMessage(buf, _sock);
}

CppsshSubChannel::CppsshSubChannel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : _session(session),
    _windowRecv(CPPSSH_RX_WINDOW_SIZE),
    _windowSend(0),
    _txChannel(0),
    _maxPacket(0),
    _channelName(channelName),
    _first(true)
{
}

