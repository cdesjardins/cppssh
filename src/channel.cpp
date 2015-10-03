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
#include "CDLogger/Logger.h"
#include "x11channel.h"
#include "visualencode.h"
#include <sstream>
#include <iomanip>
#include "debug.h"

CppsshChannel::CppsshChannel(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _mainChannel(0),
    _x11ReqSuccess(false)
{
}

CppsshChannel::~CppsshChannel()
{
    disconnect();
}

bool CppsshChannel::establish(const std::string& host, short port)
{
    bool ret = false;
    std::string channelName("session");
    if (createNewSubChannel(channelName, &_mainChannel) == true)
    {
        ret = _session->_transport->establish(host, port);
    }
    return ret;
}

bool CppsshChannel::openChannel()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_OPEN);
    try
    {
        packet.addString(_channels.at(_mainChannel)->getChannelName());
        packet.addInt(_mainChannel);

        packet.addInt(CppsshSubChannel::getRxWindowSize());
        packet.addInt(CPPSSH_MAX_PACKET_LEN);

        if (_session->_transport->sendMessage(buf) == true)
        {
            ret = _channels.at(_mainChannel)->handleChannelConfirm();
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "openChannel " << ex.what();
    }
    return ret;
}

bool CppsshChannel::isConnected()
{
    return ((_channels.find(_mainChannel) != _channels.cend()) &&
            (_session->_transport->isRunning() == true));
}

bool CppsshChannel::writeMainChannel(const uint8_t* data, uint32_t bytes)
{
    bool ret = false;
    try
    {
        std::shared_ptr<std::unique_lock<std::recursive_mutex> > lock = _channels.getLock();
        ret = _channels.at(_mainChannel)->writeChannel(data, bytes);
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "writeMainChannel " << ex.what();
    }
    return ret;
}

bool CppsshChannel::readMainChannel(CppsshMessage* data)
{
    bool ret = false;
    try
    {
        std::shared_ptr<std::unique_lock<std::recursive_mutex> > lock = _channels.getLock();
        ret = _channels.at(_mainChannel)->readChannel(data);
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "readMainChannel " << ex.what();
    }
    return ret;
}

bool CppsshChannel::windowChange(const uint32_t rows, const uint32_t cols)
{
    bool ret = false;
    try
    {
        std::shared_ptr<std::unique_lock<std::recursive_mutex> > lock = _channels.getLock();
        ret = _channels.at(_mainChannel)->windowChange(rows, cols);
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "windowChange " << ex.what();
    }
    return ret;
}

void CppsshChannel::handleDebug(const CppsshConstPacket& packet)
{
    std::string dbg;
    packet.skipHeader();
    // getByte for always display
    packet.getByte();
    if ((packet.getString(&dbg) == true) && (dbg.size() > 0))
    {
        cdLog(LogLevel::Debug) << dbg;
    }
}

void CppsshChannel::handleDisconnect(const CppsshConstPacket& packet)
{
    std::string err;
    packet.skipHeader();
    packet.getInt();
    packet.getString(&err);
    cdLog(LogLevel::Error) << err;
    disconnect();
}

void CppsshChannel::disconnect()
{
    cdLog(LogLevel::Debug) << "disconnect[" << _session->getConnectionId() << "]";
    _channels.clear();
}

void CppsshChannel::handleEof(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    _channels.at(rxChannel)->handleEof();
}

void CppsshChannel::handleClose(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    _channels.at(rxChannel)->handleClose();
    _channels.erase(rxChannel);
}

bool CppsshChannel::createNewSubChannel(const std::string& channelName, uint32_t windowSend, uint32_t maxPacket, uint32_t txChannel, uint32_t* rxChannel)
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
    std::shared_ptr<CppsshSubChannel> channel;
    if (channelName == "x11")
    {
        channel.reset(new CppsshX11Channel(_session, channelName));
    }
    else
    {
        channel.reset(new CppsshSubChannel(_session, channelName));
    }

    for (chan = 100; chan < 2048; chan++)
    {
        if (_channels.find(chan) == _channels.cend())
        {
            _channels.insert(std::pair<int, std::shared_ptr<CppsshSubChannel> >(chan, channel));
            *rxChannel = chan;
            cdLog(LogLevel::Debug) << "createNewSubChannel " << channelName << " rxChannel: " << chan;
            ret = channel->startChannel();
            break;
        }
    }
    return ret;
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
    _session->_transport->sendMessage(buf);
}

void CppsshChannel::sendOpenFailure(uint32_t rxChannel, CppsshOpenFailureReason reason)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket openFaulure(&buf);
    openFaulure.addByte(SSH2_MSG_CHANNEL_OPEN_FAILURE);
    openFaulure.addInt(rxChannel);
    openFaulure.addInt(reason);
    openFaulure.addString("Bad request");
    openFaulure.addString("EN");
    _session->_transport->sendMessage(buf);
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
        if (_x11ReqSuccess == false)
        {
            sendOpenFailure(txChannel, SSH2_OPEN_CONNECT_FAILED);
        }
        else
        {
            uint32_t rxChannel;
            if (createNewSubChannel(channelName, windowSend, maxPacket, txChannel, &rxChannel) == true)
            {
                sendOpenConfirmation(rxChannel);
            }
            else
            {
                sendOpenFailure(txChannel, SSH2_OPEN_RESOURCE_SHORTAGE);
            }
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
    std::shared_ptr<std::unique_lock<std::recursive_mutex> > lock = _channels.getLock();
    std::map<int, std::shared_ptr<CppsshSubChannel> >::const_iterator it;
    for (it = _channels.cbegin(); (it != _channels.cend() && (ret == true)); it++)
    {
        ret = it->second->flushOutgoingChannelData();
    }
    return ret;
}

bool CppsshChannel::getShell(const char* term)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addString(term);
    packet.addInt(80);
    packet.addInt(24);
    packet.addInt(0);
    packet.addInt(0);
    packet.addString("");

    try
    {
        if (_channels.at(_mainChannel)->doChannelRequest("pty-req", buf) == true)
        {
            buf.clear();
            if (_channels.at(_mainChannel)->doChannelRequest("shell", buf) == true)
            {
                ret = true;
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "getShell " << ex.what();
    }
    return ret;
}

bool CppsshChannel::getRandomString(const int size, std::string* randomString)
{
    std::vector<Botan::byte> random;
    random.resize(size / 2);
    CppsshImpl::RNG->randomize(random.data(), random.size());
    std::stringstream fake;
    for (Botan::byte it : random)
    {
        fake << std::hex << std::setw(2) << std::setfill('0') << (int)it;
    }
    *randomString = fake.str();
    return true;
}

bool CppsshChannel::getX11()
{
    bool ret = false;
    std::string display;
    CppsshX11Channel::getDisplay(&display);
    if (display.length() > 0)
    {
        if (CppsshX11Channel::runXauth(display, &_X11Method, &_realX11Cookie) == false)
        {
            getRandomString(16, &_fakeX11Cookie);
            _X11Method = "MIT-MAGIC-COOKIE-1";
        }
        else
        {
            getRandomString(_realX11Cookie.size(), &_fakeX11Cookie);
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
        try
        {
            ret = _channels.at(_mainChannel)->doChannelRequest("x11-req", x11req);
            if (ret == true)
            {
                _x11ReqSuccess = true;
            }
        }
        catch (const std::exception& ex)
        {
            cdLog(LogLevel::Error) << "getX11 " << ex.what();
        }
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
    cdLog(LogLevel::Debug) << "handleWindowAdjust " << rxChannel << " " << size;
    _channels.at(rxChannel)->increaseWindowSend(size);
}

void CppsshChannel::handleIncomingGlobalData(const Botan::secure_vector<Botan::byte>& buf)
{
    _incomingGlobalData.enqueue(buf);
}

bool CppsshChannel::waitForGlobalMessage(Botan::secure_vector<Botan::byte>& buf)
{
    return _incomingGlobalData.dequeue(buf, _session->getTimeout());
}

void CppsshChannel::handleBanner(const Botan::secure_vector<Botan::byte>& buf)
{
    std::shared_ptr<std::unique_lock<std::recursive_mutex> > lock = _channels.getLock();
    std::string banner;
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    packet.getString(&banner);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    VisualEncodeSafeOctalNoSlash vis(banner.c_str());
    message->setMessage((const uint8_t*)vis.getEncoded().c_str(), vis.getEncoded().length());
    _channels.at(_mainChannel)->handleBanner(message);
}

void CppsshChannel::handleChannelRequest(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    uint32_t rxChannel = packet.getInt();
    _channels.at(rxChannel)->handleChannelRequest(buf);
}

void CppsshChannel::handleReceived(const Botan::secure_vector<Botan::byte>& buf)
{
    const CppsshConstPacket packet(&buf);
    Botan::byte cmd = packet.getCommand();
    try
    {
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
                cdLog(LogLevel::Error) << "Unhandled SSH2_MSG_CHANNEL_EXTENDED_DATA: " << cmd;
                break;

            case SSH2_MSG_CHANNEL_EOF:
                handleEof(buf);
                break;

            case SSH2_MSG_CHANNEL_OPEN:
                handleOpen(buf);
                break;

            case SSH2_MSG_CHANNEL_CLOSE:
                handleClose(buf);
                break;

            case SSH2_MSG_CHANNEL_REQUEST:
                handleChannelRequest(buf);
                break;

            case SSH2_MSG_IGNORE:
                break;

            case SSH2_MSG_DEBUG:
                handleDebug(packet);
                break;

            case SSH2_MSG_DISCONNECT:
                handleDisconnect(packet);
                break;

            default:
                cdLog(LogLevel::Error) << "Unhandled command encountered: " << (int)cmd;
                break;
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
}

