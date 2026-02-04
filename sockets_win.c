#ifdef _WIN32
#include "sockets.h"

int ts_tcp_create(struct ts_sock *s, int family, int *out_err) {
    (void)s;
    (void)family;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_udp_create(struct ts_sock *s, int family, int *out_err) {
    (void)s;
    (void)family;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_close(struct ts_sock *s, int *out_err) {
    (void)s;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_connect(struct ts_sock *s, const struct ts_addr *addr, int timeout_ms, int *out_err) {
    (void)s;
    (void)addr;
    (void)timeout_ms;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_bind(struct ts_sock *s, const struct ts_addr *addr, int *out_err) {
    (void)s;
    (void)addr;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_listen(struct ts_sock *s, int backlog, int *out_err) {
    (void)s;
    (void)backlog;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_accept(struct ts_sock *s, struct ts_sock *out_client, struct ts_addr *out_peer, int timeout_ms,
                   int *out_err) {
    (void)s;
    (void)out_client;
    (void)out_peer;
    (void)timeout_ms;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_getsockname(struct ts_sock *s, struct ts_addr *out_addr, int *out_err) {
    (void)s;
    (void)out_addr;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_send(struct ts_sock *s, const void *buf, size_t len, int timeout_ms, size_t *out_sent, int *out_err) {
    (void)s;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    (void)out_sent;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_recv(struct ts_sock *s, void *buf, size_t len, int timeout_ms, size_t *out_got, int *out_err) {
    (void)s;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    (void)out_got;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_sendto(struct ts_sock *s, const void *buf, size_t len, const struct ts_addr *addr, int timeout_ms,
                   size_t *out_sent, int *out_err) {
    (void)s;
    (void)buf;
    (void)len;
    (void)addr;
    (void)timeout_ms;
    (void)out_sent;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_recvfrom(struct ts_sock *s, void *buf, size_t len, struct ts_addr *out_addr, int timeout_ms,
                     size_t *out_got, int *out_err) {
    (void)s;
    (void)buf;
    (void)len;
    (void)out_addr;
    (void)timeout_ms;
    (void)out_got;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_select(struct ts_sock **read_socks, int read_count, struct ts_sock **write_socks, int write_count,
              int timeout_ms, int *out_err, uint8_t *out_read_ready, uint8_t *out_write_ready) {
    (void)read_socks;
    (void)read_count;
    (void)write_socks;
    (void)write_count;
    (void)timeout_ms;
    (void)out_read_ready;
    (void)out_write_ready;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_set_nonblocking(struct ts_sock *s, int enable, int *out_err) {
    (void)s;
    (void)enable;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_set_sockopt(struct ts_sock *s, enum ts_sockopt opt, int value, int *out_err) {
    (void)s;
    (void)opt;
    (void)value;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_sock_get_sockopt(struct ts_sock *s, enum ts_sockopt opt, int *out_value, int *out_err) {
    (void)s;
    (void)opt;
    (void)out_value;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}
#endif
