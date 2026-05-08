/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _KEX_Hxx
#define _KEX_Hxx

#include "session.h"
#include "packet.h"
#include "cryptoalgos.h"
#include <memory>

class CppsshKex
{
public:
    CppsshKex(const std::shared_ptr<CppsshSession>& session);
    bool handleInit();
    bool handleKexDHReply();
    bool sendKexNewKeys();

private:
    bool sendInit(Botan::secure_vector<Botan::byte>& packet);
    bool sendKexDHInit(Botan::secure_vector<Botan::byte>& packet);
    void constructLocalKex();
    void makeH(Botan::secure_vector<Botan::byte>* hVector);
    template <typename T> T runAgreement(const CppsshConstPacket& remoteKexAlgosPacket, const CppsshAlgos<T>& algorithms, const std::string& tag) const;

    std::shared_ptr<CppsshSession> _session;
    Botan::secure_vector<Botan::byte> _localKex;
    Botan::secure_vector<Botan::byte> _remoteKex;
    Botan::secure_vector<Botan::byte> _hostKey;
    Botan::secure_vector<Botan::byte> _e;
    Botan::secure_vector<Botan::byte> _f;
    Botan::secure_vector<Botan::byte> _k;
};

#endif
