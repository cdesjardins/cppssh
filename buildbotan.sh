#!/bin/bash
pushd .
cd ../botan
./configure.py --disable-shared --disable-modules=selftest,tls --prefix=$HOME/sw/repo/install --libdir=$HOME/sw/repo/install/lib/Debug --build-mode=debug --via-amalgamation --disable-avx2 --maintainer-mode
make -j8 install
./configure.py --disable-shared --disable-modules=selftest,tls --prefix=$HOME/sw/repo/install --build-mode=release --via-amalgamation --disable-avx2 --maintainer-mode
make -j8 install
popd .
