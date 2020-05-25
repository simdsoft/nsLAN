// nsLAN.c
// V1.0
#  include <WinSock2.h>

#  include <Windows.h>
#  if defined(_WIN32) && !defined(_WINSTORE)
#    include <Mswsock.h>
#    include <Mstcpip.h>
#  endif
#  include <Ws2tcpip.h>
#  include <Wspiapi.h>
#include "nsis/pluginapi.h" // nsis plugin

#if defined(_DEBUG)
#pragma comment(lib, "ws2_32.lib")
#if !defined(UNICODE)
#pragma comment(lib, "nsis/pluginapi-x86-ansi.lib")
#else
#pragma comment(lib, "nsis/pluginapi-x86-unicode.lib")
#endif
#endif

#if !defined(UNICODE)
#define XADDRINFO addrinfo
#else
#define XADDRINFO addrinfoW
#endif

#define NSLAN_MAX_LEN 128

struct XADDRINFO* nsLanGetAddrInfo(TCHAR* addr, TCHAR* port, int af, int type, int proto)
{
    struct XADDRINFO hints, * res = NULL;

    int             rc;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = ((addr) ? 0 : AI_PASSIVE);
    hints.ai_family = af;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;

    rc = GetAddrInfo(addr, port, &hints, &res);
    if (rc == 0)
        return res;
    return NULL;
}

// To work with Unicode version of NSIS, please use TCHAR-type
// functions for accessing the variables and the stack.
void __declspec(dllexport) SendMulticastRequest(HWND hwndParent, int string_size,
    LPTSTR variables, stack_t** stacktop,
    extra_parameters* extra, ...)
{
    WSADATA dat = {0};

    // note if you want parameters from the stack, pop them off in order.
    // i.e. if you are called via exdll::myFunction file.dat read.txt
    // calling popstring() the first time would give you file.dat,
    // and the second time would give you read.txt.
    // you should empty the stack of your parameters, and ONLY your
    // parameters.
    TCHAR mcastIP[128]; // = _TEXT("224.0.0.19");
    TCHAR mcastPort[sizeof("65535")]; // = _TEXT("20524");
	TCHAR message[128];

	TCHAR* response = NULL;
#if !defined(UNICODE)
	char* buffer = message;
#else
	char buffer[NSLAN_MAX_LEN];
#endif
    int timeo            = 0; // seconds
    struct timeval tmval = {0};

    const TCHAR* error = _TEXT("fail");

    SOCKET s              = INVALID_SOCKET;
    int bytes_transferred = -1;
    fd_set fds_rd;
    struct XADDRINFO *resmulti = NULL, *resbind = NULL; //, * resif = NULL;
    struct ip_mreq mreq;                               // for multicast
    int loopback              = 1;                     // for test, enable it.
    int ttl                   = 128;
    char* last                = NULL;
    unsigned long nonblocking = 1;
    SOCKADDR_STORAGE safrom   = {0};
    int fromlen = sizeof(safrom);
	int msglen = 0;
	int resplen = 0;

    EXDLL_INIT();

    popstringn(mcastIP, NSLAN_MAX_LEN);
    popstringn(mcastPort, sizeof("65535"));
    popstringn(message, NSLAN_MAX_LEN);
    timeo        = popint();
    tmval.tv_sec = timeo;

    WSAStartup(0x0202, &dat);

    do
    {
        resmulti = nsLanGetAddrInfo(mcastIP, mcastPort, AF_INET, SOCK_DGRAM, 0);
        if (!resmulti)
            break;

        s = socket(resmulti->ai_family, resmulti->ai_socktype, resmulti->ai_protocol);
        if (s == INVALID_SOCKET)
            break;

        resbind =
            nsLanGetAddrInfo(_TEXT("0.0.0.0"), NULL, resmulti->ai_family, resmulti->ai_socktype, resmulti->ai_protocol);
        if (!resbind)
            break;

        if (bind(s, resbind->ai_addr, resbind->ai_addrlen) != 0)
            break;

        // loopback
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&loopback, sizeof(loopback));
        // ttl
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl, sizeof(ttl));

        // join to multicast
        mreq.imr_interface.s_addr = 0;
        mreq.imr_multiaddr.s_addr = ((SOCKADDR_IN*)resmulti->ai_addr)->sin_addr.s_addr;
        setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, (int)sizeof(mreq));

		msglen = lstrlen(message);
#if defined(UNICODE)
	    msglen = WideCharToMultiByte(CP_ACP, 0, message, msglen, buffer, sizeof(buffer), NULL, NULL);
#endif
        /* pitfall:
        ** Don't use connect to establish tuple with multicast addr, even through
        ** connect will succeed, and after thus, you can use 'send' to send multicast,
        ** but you never recv any data with this socket.
        */
        if (sendto(s, buffer, msglen, 0, resmulti->ai_addr, resmulti->ai_addrlen) ==
            SOCKET_ERROR)
            break;

        // when we send a multicast request, we don't care multicast, so leave.
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char*)&mreq, (int)sizeof(mreq));

        // set nonblocking
        ioctlsocket(s, FIONBIO, &nonblocking);

        FD_ZERO(&fds_rd);
        FD_SET(s, &fds_rd);
        if (select((int)(s + 1), &fds_rd, NULL, NULL, &tmval) <= 0) // timeout or error
            break;

        // ready read the reply msg
        bytes_transferred = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr*)&safrom, &fromlen);
        if (bytes_transferred <= 0)
            break;
        
        // The 'safrom' is a real host address, if you wan't only communicate with it,
        // Now you can use connect to establish tuple with 'safrom'
        last = buffer + bytes_transferred - 1;
        while (*last == '\n' || *last == '\r')
        {
            *last = '\0';
            --last;
        }
#if !defined(UNICODE)
		response = buffer;
#else
		resplen = MultiByteToWideChar(CP_ACP, 0, buffer, sizeof(buffer), message, NSLAN_MAX_LEN);
	    response = message;
		response[0] = '\0';
#endif

        error = NULL;
    } while (0);

    if (s != INVALID_SOCKET)
        closesocket(s);

    FreeAddrInfo(resmulti);
    FreeAddrInfo(resbind);
    WSACleanup();

    if (error == NULL)
        pushstring(response);
    else
        pushstring(error);
}

BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}
