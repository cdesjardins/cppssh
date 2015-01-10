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
#ifndef _IMPL_Hxx
#define _IMPL_Hxx

#include "connection.h"
#include <memory>
#include <vector>

class CppsshImpl
{
public:
    static std::shared_ptr<CppsshImpl> create();
    static void destroy();
    int connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout);
    int connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell, const int timeout);
    bool send(const char* data, size_t bytes, int channel);
    size_t read(char* data, int channel);
    bool close(int channel);
    void setOptions(const char* prefCipher, const char* prefHmac);
    bool generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);
    
private:
    std::vector<std::shared_ptr<CppsshConnection> > _connections;
};

#endif

