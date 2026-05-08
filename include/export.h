/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _EXPORT_Hxx
#define _EXPORT_Hxx

#if defined(WIN32) || defined(__MINGW32)
#ifdef CPPSSH_EXPORTS
#define CPPSSH_EXPORT __declspec(dllexport)
#else
#ifndef CPPSSH_STATIC
#define CPPSSH_EXPORT __declspec(dllimport)
#endif
#endif
#endif

#ifndef CPPSSH_EXPORT
#define CPPSSH_EXPORT
#endif

#endif
