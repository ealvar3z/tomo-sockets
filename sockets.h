#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ts_fd_t;
#define TS_INVALID_FD INVALID_SOCKET
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef int ts_fd_t;
#define TS_INVALID_FD (-1)
#endif

#define TS_OK 0
#define TS_ERR (-1)
#define TS_TIMEOUT (-2)
#define TS_CLOSED (-3)

#define TS_FAMILY_INET 4
#define TS_FAMILY_INET6 6

enum ts_sockopt {
    TS_SOCKOPT_REUSEADDR,
    TS_SOCKOPT_REUSEPORT,
    TS_SOCKOPT_TCP_NODELAY,
    TS_SOCKOPT_KEEPALIVE,
    TS_SOCKOPT_BROADCAST,
    TS_SOCKOPT_IPV6_V6ONLY,
    TS_SOCKOPT_RECV_BUF_SIZE,
    TS_SOCKOPT_SEND_BUF_SIZE
};

struct ts_sock {
    ts_fd_t fd;
    int family;
    int type;
    int protocol;
    int open;
};

struct ts_addr {
    struct sockaddr_storage ss;
    socklen_t len;
    int family;
};

static inline void ts_set_err(int *out_err, int err) {
    if (out_err != NULL) *out_err = err;
}

int ts_sock_init(int *out_err);
void ts_sock_shutdown(void);

int ts_tcp_create(struct ts_sock *s, int family, int *out_err);
int ts_udp_create(struct ts_sock *s, int family, int *out_err);
int ts_sock_close(struct ts_sock *s, int *out_err);

int ts_sock_connect(struct ts_sock *s, const struct ts_addr *addr,
                    int timeout_ms, int *out_err);
int ts_sock_bind(struct ts_sock *s, const struct ts_addr *addr, int *out_err);
int ts_sock_listen(struct ts_sock *s, int backlog, int *out_err);
int ts_sock_accept(struct ts_sock *s, struct ts_sock *out_client,
                   struct ts_addr *out_peer, int timeout_ms, int *out_err);
int ts_sock_getsockname(struct ts_sock *s, struct ts_addr *out_addr,
                        int *out_err);

int ts_sock_send(struct ts_sock *s, const void *buf, size_t len, int timeout_ms,
                 size_t *out_sent, int *out_err);
int ts_sock_recv(struct ts_sock *s, void *buf, size_t len, int timeout_ms,
                 size_t *out_got, int *out_err);
int ts_sock_sendto(struct ts_sock *s, const void *buf, size_t len,
                   const struct ts_addr *addr, int timeout_ms, size_t *out_sent,
                   int *out_err);
int ts_sock_recvfrom(struct ts_sock *s, void *buf, size_t len,
                     struct ts_addr *out_addr, int timeout_ms, size_t *out_got,
                     int *out_err);

int ts_sock_set_nonblocking(struct ts_sock *s, int enable, int *out_err);
int ts_sock_set_sockopt(struct ts_sock *s, enum ts_sockopt opt, int value,
                        int *out_err);
int ts_sock_get_sockopt(struct ts_sock *s, enum ts_sockopt opt, int *out_value,
                        int *out_err);

int ts_addr_resolve(const char *host, const char *service, int family,
                    int socktype, struct ts_addr *out_addr, int *out_err);
int ts_addr_to_string(const struct ts_addr *addr, char *host, size_t host_len,
                      char *service, size_t service_len, int *out_err);
const char *ts_addr_strerror(int err);
