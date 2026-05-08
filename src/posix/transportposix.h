/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _TRANSPORT_POSIX_Hxx
#define _TRANSPORT_POSIX_Hxx

/*
** Note: Do not include this file directly, include transport.h instead
*/

#include <memory>

class CppsshSession;

class CppsshTransportPosix : public CppsshTransportImpl
{
public:
    CppsshTransportPosix(const std::shared_ptr<CppsshSession>& session)
        : CppsshTransportImpl(session)
    {
    }

    virtual ~CppsshTransportPosix()
    {
    }

protected:
    virtual bool isConnectInProgress();
    virtual bool establishLocalX11(const std::string& display);
    virtual bool setNonBlocking(bool on);

private:
};

#endif
