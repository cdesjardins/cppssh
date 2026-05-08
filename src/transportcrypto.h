/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _TRANSPORT_CRYPTO_Hxx
#define _TRANSPORT_CRYPTO_Hxx

#include "transportthreaded.h"

class CppsshTransportCrypto : public CppsshTransportThreaded
{
public:
    CppsshTransportCrypto() = delete;
    CppsshTransportCrypto(const std::shared_ptr<CppsshSession>& session, SOCKET sock);
    virtual ~CppsshTransportCrypto();

protected:
    virtual bool sendMessage(const Botan::secure_vector<Botan::byte>& buffer);
    bool computeMac(const Botan::secure_vector<Botan::byte>& packet, uint32_t* cryptoLen);

private:
    virtual void rxThread();

    uint32_t _txSeq;
    uint32_t _rxSeq;
    Botan::secure_vector<Botan::byte> _in;
};

#endif
