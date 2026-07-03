#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

void mainCRTStartup(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443);
        addr.sin_addr.s_addr = inet_addr("203.0.113.7");
        connect(s, (struct sockaddr *)&addr, (int)sizeof(addr));
        closesocket(s);
    }
    ExitProcess(0);
}
