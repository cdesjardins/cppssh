#!/bin/bash
pushd .
cd ../botan
rm -rf build botan_all*.* libbotan*.a
./configure.py --disable-shared --disable-modules=tls --prefix=$PWD/../install --libdir=$PWD/../install/lib/botan/Debug --build-mode=debug --via-amalgamation --disable-avx2 --maintainer-mode
make -j8 install
rm -rf build botan_all*.* libbotan*.a
./configure.py --disable-shared --disable-modules=tls --prefix=$PWD/../install --libdir=$PWD/../install/lib/botan/Release --build-mode=release --via-amalgamation --disable-avx2 --maintainer-mode
make -j8 install
popd
