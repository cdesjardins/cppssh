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
    _x11RxThread.join();
    _x11TxThread.join();
}

bool CppsshX11Channel::startChannel()
{
    _x11transport.reset(new CppsshBaseTransport(_session));
    if (_x11transport->establishX11() == true)
    {
        std::cout << "starting x11 threads" << std::endl;
        _running = true;
        _x11RxThread = std::thread(&CppsshX11Channel::x11RxThread, this);
        _x11TxThread = std::thread(&CppsshX11Channel::x11TxThread, this);
    }
    return _running;
}

void CppsshX11Channel::x11RxThread()
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
            _x11transport->sendMessage(buf);
        }
    }
}

void CppsshX11Channel::x11TxThread()
{
    while (_running == true)
    {
        Botan::secure_vector<Botan::byte> x11buf;
        if (_x11transport->receiveMessage(&x11buf) == true)
        {
            writeChannel(x11buf.data(), x11buf.size());
        }
    }
}

