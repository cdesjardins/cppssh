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
#ifndef _TRANSPORT_CRYPTO_Hxx
#define _TRANSPORT_CRYPTO_Hxx

#include "transportthreaded.h"

class CppsshTransportCrypto : public CppsshTransportThreaded
{
public:
    CppsshTransportCrypto() = delete;
    CppsshTransportCrypto(const std::shared_ptr<CppsshSession>& session, SOCKET sock);
    ~CppsshTransportCrypto();

protected:
    virtual bool sendMessage(const Botan::secure_vector<Botan::byte>& buffer);
private:
    virtual void rxThread();

    uint32_t _txSeq;
    uint32_t _rxSeq;
    Botan::secure_vector<Botan::byte> _in;
};

#endif
