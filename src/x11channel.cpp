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

#include "x11channel.h"

CppsshX11Channel::CppsshX11Channel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : CppsshSubChannel(session, channelName),
    _running(false)
{
}

CppsshX11Channel::~CppsshX11Channel()
{
    _running = false;
    _x11Thread.join();
}

void CppsshX11Channel::startChannel()
{
    std::cout << "start x11" << std::endl;
    _running = true;
    _x11Thread = std::thread(&CppsshX11Channel::x11Thread, this);
}

void CppsshX11Channel::x11Thread()
{
    bool first = true;
    while (_running == true)
    {
        CppsshMessage message;
        if (readChannel(&message) == true)
        {
            Botan::secure_vector<Botan::byte> buf((Botan::byte*)message.message(), (Botan::byte*)message.message() + message.length());
            if (first == true)
            {
                CppsshPacket magicPacket(&buf);
                magicPacket.replace(message.length() - _session->_channel->_realX11Cookie.size(), _session->_channel->_realX11Cookie);
                first = false;
            }
            
            //_session->_channel->writeMainChannel(message.message(), message.length());
            //writeChannel(message.message(), message.length());
            {
                CppsshPacket p(&buf);
                p.dumpPacket("x11 stuff");
            }
            _session->_transport->CppsshBaseTransport::sendMessage(buf);
        }
    }
}
