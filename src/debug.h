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
#ifndef _DEBUG_Hxx
#define _DEBUG_Hxx

#ifndef WIN32
#include <execinfo.h>
#endif

class CppsshDebug
{
public:
    static void dumpStack(int connectionId)
    {
        cdLog(LogLevel::Debug) << "dumpStack[" << connectionId << "]";
#ifdef WIN32
#else
        void* buffer[100];
        int size;
        size = backtrace(buffer, sizeof(buffer) / sizeof(buffer[0]));
        char** stack = backtrace_symbols(buffer, size);
        for (int i = 0; i < size; i++)
        {
            cdLog(LogLevel::Debug) << stack[i];
        }
#endif
    }
};

#endif
