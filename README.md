To build botan:

Windows:
```
configure.py --disable-shared --disable-modules=selftest,tls --prefix=C:\Users\chrisd\software_devel\repo\install --enable-debug --cpu=i386 --via-amalgamation --maintainer-mode
```

Then update the makefile with:
```
CXX            = cl /MTd
```

Then move the boost includes to the top of botan_all.cpp

Linux:
```
./configure.py --disable-shared --disable-modules=selftest,tls --prefix=$HOME/sw/repo/install --build-mode=debug --via-amalgamation --disable-avx2 --maintainer-mode
```
