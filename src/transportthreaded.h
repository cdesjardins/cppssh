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
#ifndef _TRANSPORT_THREADED_Hxx
#define _TRANSPORT_THREADED_Hxx

#include "transport.h"
class CppsshTransportThreaded : public CppsshTransport
{
public:
    CppsshTransportThreaded(const std::shared_ptr<CppsshSession>& session);
    virtual ~CppsshTransportThreaded();
    bool start();
    virtual bool sendMessage(const Botan::secure_vector<Botan::byte>& buffer);

protected:
    bool setupMessage(const Botan::secure_vector<Botan::byte>& buffer, Botan::secure_vector<Botan::byte>* outBuf);

    virtual void rxThread();
    virtual void txThread();

    std::thread _rxThread;
    std::thread _txThread;
};

#endif