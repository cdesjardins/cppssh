/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _CHANNEL_Hxx
#define _CHANNEL_Hxx

#include "packet.h"
#include "session.h"
#include "messages.h"
#include "transport.h"
#include "threadsafemap.h"
#include "threadsafequeue.h"

class CppsshSubChannel;

class CppsshChannel
{
public:
    CppsshChannel(const std::shared_ptr<CppsshSession>& session);
    ~CppsshChannel();
    bool establish(const std::string& host, short port);
    bool openChannel();
    bool writeMainChannel(const uint8_t* data, uint32_t bytes);
    bool readMainChannel(CppsshMessage* data);
    bool windowChange(const uint32_t rows, const uint32_t cols);
    bool getShell(const char* term);
    bool getX11();
    void handleReceived(const Botan::secure_vector<Botan::byte>& buf);
    bool flushOutgoingChannelData();
    void disconnect();
    bool isConnected();
    bool waitForGlobalMessage(Botan::secure_vector<Botan::byte>& buf);
    static bool getRandomString(const int size, std::string* randomString);
private:
    void handleIncomingChannelData(const Botan::secure_vector<Botan::byte>& buf);
    void handleIncomingControlData(const Botan::secure_vector<Botan::byte>& buf);
    void handleWindowAdjust(const Botan::secure_vector<Botan::byte>& buf);
    void handleIncomingGlobalData(const Botan::secure_vector<Botan::byte>& buf);
    void handleChannelRequest(const Botan::secure_vector<Botan::byte>& buf);
    void handleBanner(const Botan::secure_vector<Botan::byte>& buf);
    void handleEof(const Botan::secure_vector<Botan::byte>& buf);
    void handleClose(const Botan::secure_vector<Botan::byte>& buf);

    void handleDebug(const CppsshConstPacket& packet);
    void handleDisconnect(const CppsshConstPacket& packet);
    void handleOpen(const Botan::secure_vector<Botan::byte>& buf);
    bool runXauth(const char* display, std::string* method, Botan::secure_vector<Botan::byte>* cookie) const;
    bool createNewSubChannel(const std::string& channelName, uint32_t windowSend, uint32_t maxPacket, uint32_t txChannel, uint32_t* rxChannel);
    bool createNewSubChannel(const std::string& channelName, uint32_t* rxChannel);
    void sendOpenFailure(uint32_t txChannel, CppsshOpenFailureReason reason);
    void sendOpenConfirmation(uint32_t rxChannel);

    std::shared_ptr<CppsshSession> _session;
    std::string _X11Method;
    Botan::secure_vector<Botan::byte> _realX11Cookie;
    std::string _fakeX11Cookie;

    ThreadSafeQueue<Botan::secure_vector<Botan::byte> > _incomingGlobalData;
    ThreadSafeMap<int, std::shared_ptr<CppsshSubChannel> > _channels;
    uint32_t _mainChannel;
    bool _x11ReqSuccess;
    friend class CppsshX11Channel;
};

#endif
