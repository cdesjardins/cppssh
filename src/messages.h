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
#ifndef _MESSAGES_Hxx
#define _MESSAGES_Hxx

#define SSH2_MSG_DISCONNECT                             1
#define SSH2_MSG_IGNORE                                 2

#define SSH2_MSG_KEXINIT                                20
#define SSH2_MSG_NEWKEYS                                21

#define SSH2_MSG_KEXDH_INIT                             30
#define SSH2_MSG_KEXDH_REPLY                            31

#define SSH2_MSG_SERVICE_REQUEST                        5
#define SSH2_MSG_SERVICE_ACCEPT                         6

#define SSH2_MSG_USERAUTH_REQUEST                       50
#define SSH2_MSG_USERAUTH_FAILURE                       51
#define SSH2_MSG_USERAUTH_SUCCESS                       52
#define SSH2_MSG_USERAUTH_BANNER                        53
#define SSH2_MSG_USERAUTH_PK_OK                         60

#define SSH2_MSG_CHANNEL_OPEN                           90
#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION              91
#define SSH2_MSG_CHANNEL_OPEN_FAILURE                   92
#define SSH2_MSG_CHANNEL_WINDOW_ADJUST                  93
#define SSH2_MSG_CHANNEL_DATA                           94
#define SSH2_MSG_CHANNEL_EXTENDED_DATA                  95
#define SSH2_MSG_CHANNEL_EOF                            96
#define SSH2_MSG_CHANNEL_CLOSE                          97
#define SSH2_MSG_CHANNEL_REQUEST                        98
#define SSH2_MSG_CHANNEL_SUCCESS                        99
#define SSH2_MSG_CHANNEL_FAILURE                        100

#endif