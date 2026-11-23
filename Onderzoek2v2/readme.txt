Vereisten: Visual Studio 2022 met "Desktop development with C++" en Git
Eenmalig vcpkg en openssl installeren:
1:
git clone https://github.com/microsoft/vcpkg C:\vcpkg

2:
C:\vcpkg\bootstrap-vcpkg.bat

3:
C:\vcpkg\vcpkg install openssl:x64-windows

4:
C:\vcpkg\vcpkg.exe integrate install
