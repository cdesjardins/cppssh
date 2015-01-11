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
