To build botan:

Windows:
```
configure.py --disable-shared --disable-modules=mce,selftest,tls,ffi,mceies,curve25519 --prefix=C:\Users\chrisd\software_devel\repo\botan\install --enable-debug --cpu=i386 --via-amalgamation --with-boost
```

Then update the makefile with:
```
CXX            = cl /MTd
LIB_OPT        = /Od /Zi /DDEBUG /DBOOST_ALL_NO_LIB /IC:\Users\chrisd\software_devel\repo\boost\boost_1_57_0
APP_OPT        = /Od /Zi /DDEBUG /D_CONSOLE /DBOOST_ALL_NO_LIB /IC:\Users\chrisd\software_devel\repo\boost\boost_1_57_0
LANG_FLAGS     = /EHs /GR
WARN_FLAGS     = /W3 /wd4275 /wd4267
SO_OBJ_FLAGS   = 

LIB_LINK_CMD   = $(CXX) /LD

LIB_EXTRA = C:\Users\chrisd\software_devel\repo\boost\boost_1_57_0\stage\debug\libboost_filesystem.lib C:\Users\chrisd\software_devel\repo\boost\boost_1_57_0\stage\debug\libboost_system.lib
LIB_LINKS_TO   = advapi32.lib user32.lib $(LIB_EXTRA)
APP_LINKS_TO   = $(LIB_LINKS_TO)
TEST_LINKS_TO  = $(LIB_LINKS_TO)

LIB_FLAGS      = $(SO_OBJ_FLAGS) $(LANG_FLAGS) $(LIB_OPT) $(WARN_FLAGS)
APP_FLAGS      = $(LANG_FLAGS) $(APP_OPT) $(WARN_FLAGS)
TEST_FLAGS     = $(LANG_FLAGS) $(APP_OPT) $(WARN_FLAGS)
```

Then move the boost includes to the top of botan_all.cpp

Linux:
```
./configure.py --disable-shared --disable-modules=mce,selftest,tls,ffi --prefix=/home/chrisd/sw/repo/botan/install --enable-debug --via-amalgamation
```