#!/bin/bash
#repo init -u https://github.com/cdesjardins/cppsshManifest.git 
#repo sync

curl https://raw.githubusercontent.com/cdesjardins/ComBomb/master/makeboost.py > makeboost.py
chmod +x makeboost.py
#./makeboost.py
#./buildbotan.sh

function runCmake {
    mkdir build
    cd build
    rm -rf *
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j8 install
    rm -rf *
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    make -j8 install
}

cd ../CDLogger
runCmake

cd ../../QueuePtr
runCmake

cd ../../cppssh
runCmake

