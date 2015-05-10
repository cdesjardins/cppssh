To build botan:

Windows:
```
configure.py --disable-shared --disable-modules=selftest,tls --prefix=%USERPROFILE%\software_devel\repo\install --build-mode=debug --cpu=i386 --via-amalgamation --maintainer-mode
```

Then update the makefile with:
```
CXX            = cl /MTd
```

Linux:
```
./configure.py --disable-shared --disable-modules=selftest,tls --prefix=$HOME/sw/repo/install --build-mode=debug --via-amalgamation --disable-avx2 --maintainer-mode
```
