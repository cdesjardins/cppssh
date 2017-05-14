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
#include "cppssh.h"
#include "session.h"
#include "subchannel.h"
#include "messages.h"

#define CPPSSH_RX_WINDOW_SIZE (CPPSSH_MAX_PACKET_LEN * 150)

CppsshSubChannel::CppsshSubChannel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : _session(session),
    _windowRecv(CPPSSH_RX_WINDOW_SIZE),
    _windowSend(0),
    _txChannel(0),
    _maxPacket(0),
    _channelName(channelName)
{
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
    _session->_transport->sendMessage(buf);
}

void CppsshSubChannel::handleEof()
{
    cdLog(LogLevel::Debug) << "handleeof " << _channelName << " txChannel: " << _txChannel;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_EOF);
    packet.addInt(_txChannel);
    _session->_transport->sendMessage(buf);
}

void CppsshSubChannel::handleClose()
{
    cdLog(LogLevel::Debug) << "handleclose " << _channelName << " txChannel: " << _txChannel;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_CLOSE);
    packet.addInt(_txChannel);
    _session->_transport->sendMessage(buf);
}

void CppsshSubChannel::handleChannelRequest(const Botan::secure_vector<Botan::byte>& buf)
{
    Botan::byte response = SSH2_MSG_CHANNEL_FAILURE;
    std::string request;

    CppsshConstPacket packet(&buf);
    packet.skipHeader();
    packet.getInt();
    packet.getString(&request);
    Botan::byte wantReply = packet.getByte();
    if (request == "exit-status")
    {
        response = SSH2_MSG_CHANNEL_SUCCESS;
    }
    else if ((request == "pty-req") || (request == "x11-req") || (request == "env") ||
             (request == "shell") || (request == "exec") || (request == "subsystem") ||
             (request == "window-change") || (request == "xon-xoff") || (request == "signal") ||
             (request == "exit-status") || (request == "exit-signal"))
    {
        cdLog(LogLevel::Error) << "Unhandled channel request: " << request;
    }
    else
    {
        cdLog(LogLevel::Error) << "Unknown channel request: " << request;
    }
    if (wantReply != 0)
    {
        Botan::secure_vector<Botan::byte> resp;
        CppsshPacket respPkt(&resp);
        respPkt.addByte(response);
        respPkt.addInt(_txChannel);
        _session->_transport->sendMessage(resp);
    }
}

void CppsshSubChannel::handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf)
{
    CppsshConstPacket packet(&buf);
    std::shared_ptr<CppsshMessage> message(new CppsshMessage());
    packet.skipHeader();
    // rx channel
    /*uint32_t rxChannel = */ packet.getInt();
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
    CppsshConstPacket packet(&buf);
}

void CppsshSubChannel::setParameters(uint32_t windowSend, uint32_t txChannel, uint32_t maxPacket)
{
    _windowSend = windowSend;
    _txChannel = txChannel;
    _maxPacket = maxPacket;
}

bool CppsshSubChannel::flushOutgoingChannelData()
{
    bool ret = true;
    while (_outgoingChannelData.size() > 0)
    {
        std::shared_ptr<Botan::secure_vector<Botan::byte> > message;
        if ((_outgoingChannelData.dequeue(message, 1) == true) && (message->size() > 0))
        {
            _windowSend -= message->size();
            Botan::secure_vector<Botan::byte> buf;
            CppsshPacket packet(&buf);
            packet.addByte(SSH2_MSG_CHANNEL_DATA);
            packet.addInt(_txChannel);
            packet.addInt(message->size());
            packet.addVector(*message);
            ret = _session->_transport->sendMessage(buf);
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

bool CppsshSubChannel::readChannel(CppsshMessage* data)
{
    std::shared_ptr<CppsshMessage> m;
    bool ret = _incomingChannelData.dequeue(m, 1);
    if (ret == true)
    {
        *data = *m;
    }
    return ret;
}

bool CppsshSubChannel::windowChange(const uint32_t cols, const uint32_t rows)
{
    bool ret;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    cdLog(LogLevel::Debug) << "windowChange[" << _session->getConnectionId() << "]: (" << cols << ", " << rows << ")";

    packet.addInt(cols);
    packet.addInt(rows);
    packet.addInt(0);
    packet.addInt(0);
    ret = doChannelRequest("window-change", buf, false);
    return ret;
}

bool CppsshSubChannel::handleChannelConfirm()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    if (_incomingControlData.dequeue(buf, _session->getTimeout()) == false)
    {
        cdLog(LogLevel::Error) << "New channel: " << /* channelId << FIXME: rx channel id */ " could not be open. ";
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

bool CppsshSubChannel::doChannelRequest(const std::string& req, const Botan::secure_vector<Botan::byte>& reqdata,
                                        bool wantReply)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    packet.addByte(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_txChannel);
    packet.addString(req);
    packet.addByte(wantReply);// want reply == true
    packet.addVector(reqdata);

    if (_session->_transport->sendMessage(buf) == true)
    {
        if (wantReply == true)
        {
            if ((_incomingControlData.dequeue(buf, _session->getTimeout()) == true) &&
                (packet.getCommand() == SSH2_MSG_CHANNEL_SUCCESS))
            {
                ret = true;
            }
            else
            {
                cdLog(LogLevel::Error) << "Unable to send channel request: " << req;
            }
        }
        else
        {
            ret = true;
        }
    }
    return ret;
}

void CppsshSubChannel::handleBanner(const std::shared_ptr<CppsshMessage>& banner)
{
    _incomingChannelData.enqueue(banner);
}

uint32_t CppsshSubChannel::getRxWindowSize()
{
    return CPPSSH_RX_WINDOW_SIZE;
}
