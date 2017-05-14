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
#ifndef _X11_CHANNEL_Hxx
#define _X11_CHANNEL_Hxx

#include "channel.h"
#include "subchannel.h"
#include <thread>

class CppsshX11Channel : public CppsshSubChannel
{
public:
    CppsshX11Channel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName);
    CppsshX11Channel() = delete;
    CppsshX11Channel(const CppsshX11Channel&) = delete;
    ~CppsshX11Channel();
    virtual bool startChannel();
    static void getDisplay(std::string* display);
    static bool runXauth(const std::string& display, std::string* method, Botan::secure_vector<Botan::byte>* cookie);

protected:
    void disconnect();
    void x11RxThread();
    void x11TxThread();
    std::unique_ptr<CppsshTransport> _x11transport;

    std::thread _x11RxThread;
    std::thread _x11TxThread;
private:
};

#endif
