/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _TRANSPORT_THREADED_Hxx
#define _TRANSPORT_THREADED_Hxx

#include "transport.h"
#include <thread>

class CppsshTransportThreaded : public CppsshTransport
{
public:
    CppsshTransportThreaded(const std::shared_ptr<CppsshSession>& session);
    virtual ~CppsshTransportThreaded();
    bool startThreads() override;
    virtual bool sendMessage(const Botan::secure_vector<Botan::byte>& buffer);

protected:
    bool processIncomingData(Botan::secure_vector<Botan::byte>* inBuf, const Botan::secure_vector<Botan::byte>& incoming, uint32_t dataLen) const;
    bool setupMessage(const Botan::secure_vector<Botan::byte>& buffer, Botan::secure_vector<Botan::byte>* outBuf);
    void stopThreads();

    virtual void rxThread();
    virtual void txThread();

    std::thread _rxThread;
    std::thread _txThread;
};

#endif
