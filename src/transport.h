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
#ifndef _TRANSPORT_Hxx
#define _TRANSPORT_Hxx

#ifdef WIN32
class CppsshTransportWin;
typedef class CppsshTransportWin CppsshTransport;
#include <winsock.h>
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
