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
#ifndef _CPPSSH_Hxx
#define _CPPSSH_Hxx

#include "export.h"
#include <cstdlib>
#include <memory>

class CppsshImpl;

class Cppssh
{
public:
    CPPSSH_EXPORT static void create();
    CPPSSH_EXPORT static void destroy();
    CPPSSH_EXPORT static int connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell = true);
    CPPSSH_EXPORT static int connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell = true);
    CPPSSH_EXPORT static bool send(const char* data, size_t bytes, int channel);
    CPPSSH_EXPORT static size_t read(char* data, int channel);
    CPPSSH_EXPORT static bool close(int channel);
    CPPSSH_EXPORT static void setOptions(const char* prefCipher, const char* prefHmac);
    CPPSSH_EXPORT static bool generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize = 0);

private:
    static std::shared_ptr<CppsshImpl> s_cppsshInst;
    Cppssh();
    Cppssh(const Cppssh&);
    Cppssh& operator=(const Cppssh&);

};

#endif
