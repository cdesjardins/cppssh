#!/bin/bash
~/Downloads/cppcheck-1.69/cppcheck -Iinclude/ -I../botan/install/include/botan-1.11/ -I../CDLogger/include/ --std=c++11 --enable=all --force  . 2> err.txt
call_Uncrustify.sh . cpp
call_Uncrustify.sh . h
cat err.txt
