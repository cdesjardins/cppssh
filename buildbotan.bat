pushd .
cd ..\botan
del /s /q build botan_all*.* botan*.lib botan*.exe *.dll
configure.py --disable-shared --disable-modules=tls --build-mode=release --cpu=i386 --via-amalgamation --maintainer-mode --prefix=%USERPROFILE%\software_devel\repo\install --libdir=%USERPROFILE%\software_devel\repo\install\lib\botan\Release
sed -i 's/cl \/MD/cl \/MT/' Makefile
nmake install
copy botan-111.lib %USERPROFILE%\software_devel\repo\install\lib\botan\Release
del /s /q build botan_all*.* botan*.lib botan*.exe *.dll
configure.py --disable-shared --disable-modules=tls --build-mode=debug   --cpu=i386 --via-amalgamation --maintainer-mode --prefix=%USERPROFILE%\software_devel\repo\install --libdir=%USERPROFILE%\software_devel\repo\install\lib\botan\Debug
sed -i 's/cl \/MD/cl \/MT/' Makefile
nmake install
copy botan-111.lib %USERPROFILE%\software_devel\repo\install\lib\botan\Debug
popd