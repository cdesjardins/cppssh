/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
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
