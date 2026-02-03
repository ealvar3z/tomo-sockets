#include "sockets.h"

#ifdef _WIN32
int ts_sock_init(int *out_err) {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        ts_set_err(out_err, WSAGetLastError());
        return TS_ERR;
    }

    return TS_OK;
}

void ts_sock_shutdown(void) {
    WSACleanup();
}
#else
int ts_sock_init(int *out_err) {
    (void)out_err;
    return TS_OK;
}

void ts_sock_shutdown(void) {
}
#endif
