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
#include "cppssh.h"
#include "unparam.h"
#include <iterator>

CppsshX11Channel::CppsshX11Channel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : CppsshSubChannel(session, channelName)
{
    cdLog(LogLevel::Debug) << "CppsshX11Channel";
}

CppsshX11Channel::~CppsshX11Channel()
{
    cdLog(LogLevel::Debug) << "~CppsshX11Channel";
    disconnect();
}

void CppsshX11Channel::disconnect()
{
    if (_x11transport != nullptr)
    {
        _x11transport->disconnect();
    }
    if (_x11RxThread.joinable() == true)
    {
        _x11RxThread.join();
    }
    if (_x11TxThread.joinable() == true)
    {
        _x11TxThread.join();
    }
    _x11transport.reset();
}

bool CppsshX11Channel::startChannel()
{
    bool ret = false;
    cdLog(LogLevel::Debug) << "startChannel";
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
    cdLog(LogLevel::Debug) << "starting x11 rx thread";
    while (_x11transport->isRunning() == true)
    {
        CppsshMessage message;
        if (readChannel(&message) == true)
        {
            Botan::secure_vector<Botan::byte> buf((Botan::byte*)message.message(),
                                                  (Botan::byte*)message.message() + message.length());
            if (first == true)
            {
                CppsshPacket magicPacket(&buf);
                magicPacket.replace(
                    message.length() - _session->_channel->_realX11Cookie.size(), _session->_channel->_realX11Cookie);
                first = false;
            }
            _x11transport->sendMessage(buf);
        }
    }
    cdLog(LogLevel::Debug) << "x11 rx thread done";
}

void CppsshX11Channel::x11TxThread()
{
    cdLog(LogLevel::Debug) << "starting x11 tx thread " << _txChannel;
    while (_x11transport->isRunning() == true)
    {
        Botan::secure_vector<Botan::byte> buf;
        if ((_x11transport->receiveMessage(&buf) == true) && (buf.size() > 0))
        {
            writeChannel(buf.data(), buf.size());
        }
    }
    cdLog(LogLevel::Debug) << "x11 tx thread done " << _txChannel;
}

void CppsshX11Channel::getDisplay(std::string* display)
{
    char* d = getenv("DISPLAY");
    if (d != nullptr)
    {
        *display = d;
    }
    if (display->length() == 0)
    {
        *display = ":0";
    }
}

bool CppsshX11Channel::runXauth(const std::string& display, std::string* method,
                                Botan::secure_vector<Botan::byte>* cookie)
{
    bool ret = false;
#ifndef WIN32
    std::stringstream xauth;
    std::string tmpname;
    CppsshChannel::getRandomString(16, &tmpname);
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
            else
            {
                cdLog(LogLevel::Error) << "Invalid magic string from xauth: " << magic;
            }
        }
        else
        {
            cdLog(LogLevel::Error) << "Unable to read magic file: " << tmpname;
        }
    }
    else
    {
        cdLog(LogLevel::Error) << "Unable to run command: " << xauth.str();
    }
    remove(tmpname.c_str());
#else
    UNREF_PARAM(display);
    UNREF_PARAM(method);
    UNREF_PARAM(cookie);
#endif
    return ret;
}

