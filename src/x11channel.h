/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
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
