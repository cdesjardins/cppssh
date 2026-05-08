/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _TRANSPORT_Hxx
#define _TRANSPORT_Hxx

#ifdef WIN32
class CppsshTransportWin;
typedef class CppsshTransportWin CppsshTransport;
#include <winsock2.h>
#include <ws2tcpip.h>
#else
class CppsshTransportPosix;
typedef class CppsshTransportPosix CppsshTransport;
#define SOCKET int
#endif

#include "transportimpl.h"

#ifdef WIN32
#include "win/transportwin.h"
#else
#include "posix/transportposix.h"
#endif

#endif
