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
#include <iterator>

CppsshX11Channel::CppsshX11Channel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : CppsshSubChannel(session, channelName)
{
}

CppsshX11Channel::~CppsshX11Channel()
{
    disconnect();
}

void CppsshX11Channel::disconnect()
{
    if (_x11transport != NULL)
    {
        _x11transport->disconnect();
    }
    _x11RxThread.join();
    _x11TxThread.join();
    _x11transport.reset();
}

bool CppsshX11Channel::startChannel()
{
    bool ret = false;
    _x11transport.reset(new CppsshTransport(_session));
    if (_x11transport->establishX11() == true)
    {
        ret = true;
        _x11RxThread = std::thread(&CppsshX11Channel::x11RxThread, this);
        _x11TxThread = std::thread(&CppsshX11Channel::x11TxThread, this);
    }
    return ret;
}

void CppsshX11Channel::x11RxThread()
{
    bool first = true;
    std::cout << "starting x11 rx thread" << std::endl;
    while (_x11transport->isRunning() == true)
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
    std::cout << "x11 rx thread done" << std::endl;
}

void CppsshX11Channel::x11TxThread()
{
    std::cout << "starting x11 tx thread" << std::endl;
    while (_x11transport->isRunning() == true)
    {
        Botan::secure_vector<Botan::byte> buf;
        if (_x11transport->receiveMessage(&buf) == true)
        {
            writeChannel(buf.data(), buf.size());
        }
    }
    std::cout << "x11 tx thread done" << std::endl;
}

void CppsshX11Channel::getDisplay(std::string* display)
{
    char* d = getenv("DISPLAY");
    if (d != NULL)
    {
        *display = d;
    }
    if (display->length() == 0)
    {
        *display = ":0";
    }
}

bool CppsshX11Channel::runXauth(const std::string& display, std::string* method, Botan::secure_vector<Botan::byte>* cookie)
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

