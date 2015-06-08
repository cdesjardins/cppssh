pushd .
cd ..\botan
del /s /q build botan_all*.* botan*.lib botan*.exe
configure.py --disable-shared --disable-modules=selftest,tls --build-mode=release --cpu=i386 --via-amalgamation --maintainer-mode --prefix=%USERPROFILE%\software_devel\repo\install
sed -i 's/cl \/MD/cl \/MT/' Makefile
nmake install
del /s /q build botan_all*.* botan*.lib botan*.exe
configure.py --disable-shared --disable-modules=selftest,tls --build-mode=debug   --cpu=i386 --via-amalgamation --maintainer-mode --prefix=%USERPROFILE%\software_devel\repo\install --libdir=%USERPROFILE%\software_devel\repo\install\lib\Debug
sed -i 's/cl \/MD/cl \/MT/' Makefile
nmake install
popd