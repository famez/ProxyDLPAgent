ProxyDLP agent. In construction.

To compile: x86_64-w64-mingw32-gcc proxydlp.c -o proxydlp.exe -I"$(pwd)" -L"$(pwd)" -lWinDivert -lws2_32

Is uses the WinDivert software (dll+driver). Uploaded to the repo.

For more information of WinDivert, go to the author web page: https://reqrypt.org/windivert.html

Depends also on the WinSock2 library.

Versions of the dependencies:

Windivert: 2.2.2
curl: 8.15.0