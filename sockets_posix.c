#ifndef _WIN32
#include "sockets.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

static void ts_sock_init_struct(struct ts_sock *s, int family, int type, int protocol) {
    s->fd = TS_INVALID_FD;
    s->family = family;
    s->type = type;
    s->protocol = protocol;
    s->open = 0;
}

static int ts_wait_fd(int fd, short events, int timeout_ms, int *out_err) {
    struct pollfd pfd;
    int ret;

    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;

    for (;;) {
        ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0) return TS_OK;
        if (ret == 0) return TS_TIMEOUT;
        if (errno == EINTR) continue;
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
}

int ts_tcp_create(struct ts_sock *s, int family, int *out_err) {
    ts_sock_init_struct(s, family, SOCK_STREAM, IPPROTO_TCP);
    s->fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s->fd == TS_INVALID_FD) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    s->open = 1;
    return TS_OK;
}

int ts_udp_create(struct ts_sock *s, int family, int *out_err) {
    ts_sock_init_struct(s, family, SOCK_DGRAM, IPPROTO_UDP);
    s->fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s->fd == TS_INVALID_FD) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    s->open = 1;
    return TS_OK;
}

int ts_sock_close(struct ts_sock *s, int *out_err) {
    if (s == NULL || s->open == 0) return TS_OK;
    if (close(s->fd) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    s->fd = TS_INVALID_FD;
    s->open = 0;
    return TS_OK;
}

int ts_sock_connect(struct ts_sock *s, const struct ts_addr *addr, int timeout_ms, int *out_err) {
    int flags;
    int ret;

    if (timeout_ms <= 0) {
        if (connect(s->fd, (const struct sockaddr *)&addr->ss, addr->len) != 0) {
            ts_set_err(out_err, errno);
            return TS_ERR;
        }
        return TS_OK;
    }

    flags = fcntl(s->fd, F_GETFL, 0);
    if (flags == -1) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (fcntl(s->fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    ret = connect(s->fd, (const struct sockaddr *)&addr->ss, addr->len);
    if (ret == 0) {
        (void)fcntl(s->fd, F_SETFL, flags);
        return TS_OK;
    }

    if (errno != EINPROGRESS) {
        ts_set_err(out_err, errno);
        (void)fcntl(s->fd, F_SETFL, flags);
        return TS_ERR;
    }

    ret = ts_wait_fd(s->fd, POLLOUT, timeout_ms, out_err);
    if (ret != TS_OK) {
        (void)fcntl(s->fd, F_SETFL, flags);
        return ret;
    }

    {
        int soerr = 0;
        socklen_t len = sizeof(soerr);
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0) {
            ts_set_err(out_err, errno);
            (void)fcntl(s->fd, F_SETFL, flags);
            return TS_ERR;
        }
        if (soerr != 0) {
            ts_set_err(out_err, soerr);
            (void)fcntl(s->fd, F_SETFL, flags);
            return TS_ERR;
        }
    }

    (void)fcntl(s->fd, F_SETFL, flags);
    return TS_OK;
}

int ts_sock_bind(struct ts_sock *s, const struct ts_addr *addr, int *out_err) {
    if (bind(s->fd, (const struct sockaddr *)&addr->ss, addr->len) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    return TS_OK;
}

int ts_sock_listen(struct ts_sock *s, int backlog, int *out_err) {
    if (listen(s->fd, backlog) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    return TS_OK;
}

int ts_sock_accept(struct ts_sock *s, struct ts_sock *out_client, struct ts_addr *out_peer, int timeout_ms,
                   int *out_err) {
    socklen_t len = sizeof(out_peer->ss);
    int fd;

    if (timeout_ms > 0) {
        int ready = ts_wait_fd(s->fd, POLLIN, timeout_ms, out_err);
        if (ready != TS_OK) return ready;
    }

    fd = accept(s->fd, (struct sockaddr *)&out_peer->ss, &len);
    if (fd == TS_INVALID_FD) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    out_peer->len = len;
    out_peer->family = ((struct sockaddr *)&out_peer->ss)->sa_family;

    ts_sock_init_struct(out_client, out_peer->family, s->type, s->protocol);
    out_client->fd = fd;
    out_client->open = 1;
    return TS_OK;
}

int ts_sock_getsockname(struct ts_sock *s, struct ts_addr *out_addr, int *out_err) {
    socklen_t len = sizeof(out_addr->ss);

    if (getsockname(s->fd, (struct sockaddr *)&out_addr->ss, &len) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    out_addr->len = len;
    out_addr->family = ((struct sockaddr *)&out_addr->ss)->sa_family;
    return TS_OK;
}

int ts_sock_send(struct ts_sock *s, const void *buf, size_t len, int timeout_ms, size_t *out_sent, int *out_err) {
    ssize_t n;

    if (timeout_ms > 0) {
        int ready = ts_wait_fd(s->fd, POLLOUT, timeout_ms, out_err);
        if (ready != TS_OK) return ready;
    }

    n = send(s->fd, buf, len, 0);
    if (n < 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (out_sent != NULL) *out_sent = (size_t)n;
    return TS_OK;
}

int ts_sock_recv(struct ts_sock *s, void *buf, size_t len, int timeout_ms, size_t *out_got, int *out_err) {
    ssize_t n;

    if (timeout_ms > 0) {
        int ready = ts_wait_fd(s->fd, POLLIN, timeout_ms, out_err);
        if (ready != TS_OK) return ready;
    }

    n = recv(s->fd, buf, len, 0);
    if (n < 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (n == 0) return TS_CLOSED;

    if (out_got != NULL) *out_got = (size_t)n;
    return TS_OK;
}

int ts_sock_sendto(struct ts_sock *s, const void *buf, size_t len, const struct ts_addr *addr, int timeout_ms,
                   size_t *out_sent, int *out_err) {
    ssize_t n;

    if (timeout_ms > 0) {
        int ready = ts_wait_fd(s->fd, POLLOUT, timeout_ms, out_err);
        if (ready != TS_OK) return ready;
    }

    n = sendto(s->fd, buf, len, 0, (const struct sockaddr *)&addr->ss, addr->len);
    if (n < 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (out_sent != NULL) *out_sent = (size_t)n;
    return TS_OK;
}

int ts_sock_recvfrom(struct ts_sock *s, void *buf, size_t len, struct ts_addr *out_addr, int timeout_ms,
                     size_t *out_got, int *out_err) {
    socklen_t alen = sizeof(out_addr->ss);
    ssize_t n;

    if (timeout_ms > 0) {
        int ready = ts_wait_fd(s->fd, POLLIN, timeout_ms, out_err);
        if (ready != TS_OK) return ready;
    }

    n = recvfrom(s->fd, buf, len, 0, (struct sockaddr *)&out_addr->ss, &alen);
    if (n < 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    out_addr->len = alen;
    out_addr->family = ((struct sockaddr *)&out_addr->ss)->sa_family;

    if (out_got != NULL) *out_got = (size_t)n;
    return TS_OK;
}

int ts_sock_set_nonblocking(struct ts_sock *s, int enable, int *out_err) {
    int flags;

    flags = fcntl(s->fd, F_GETFL, 0);
    if (flags == -1) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (enable) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;

    if (fcntl(s->fd, F_SETFL, flags) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    return TS_OK;
}

static int ts_sockopt_to_level_name(enum ts_sockopt opt, int *out_level, int *out_name) {
    switch (opt) {
    case TS_SOCKOPT_REUSEADDR:
        *out_level = SOL_SOCKET;
        *out_name = SO_REUSEADDR;
        return TS_OK;
    case TS_SOCKOPT_REUSEPORT:
#ifdef SO_REUSEPORT
        *out_level = SOL_SOCKET;
        *out_name = SO_REUSEPORT;
        return TS_OK;
#else
        return TS_ERR;
#endif
    case TS_SOCKOPT_TCP_NODELAY:
        *out_level = IPPROTO_TCP;
        *out_name = TCP_NODELAY;
        return TS_OK;
    case TS_SOCKOPT_KEEPALIVE:
        *out_level = SOL_SOCKET;
        *out_name = SO_KEEPALIVE;
        return TS_OK;
    case TS_SOCKOPT_BROADCAST:
        *out_level = SOL_SOCKET;
        *out_name = SO_BROADCAST;
        return TS_OK;
    case TS_SOCKOPT_IPV6_V6ONLY:
        *out_level = IPPROTO_IPV6;
        *out_name = IPV6_V6ONLY;
        return TS_OK;
    case TS_SOCKOPT_RECV_BUF_SIZE:
        *out_level = SOL_SOCKET;
        *out_name = SO_RCVBUF;
        return TS_OK;
    case TS_SOCKOPT_SEND_BUF_SIZE:
        *out_level = SOL_SOCKET;
        *out_name = SO_SNDBUF;
        return TS_OK;
    default: return TS_ERR;
    }
}

int ts_sock_set_sockopt(struct ts_sock *s, enum ts_sockopt opt, int value, int *out_err) {
    int level;
    int name;
    int val = value;

    if (ts_sockopt_to_level_name(opt, &level, &name) != TS_OK) {
        ts_set_err(out_err, ENOPROTOOPT);
        return TS_ERR;
    }

    if (setsockopt(s->fd, level, name, &val, sizeof(val)) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    return TS_OK;
}

int ts_sock_get_sockopt(struct ts_sock *s, enum ts_sockopt opt, int *out_value, int *out_err) {
    int level;
    int name;
    int val = 0;
    socklen_t len = sizeof(val);

    if (ts_sockopt_to_level_name(opt, &level, &name) != TS_OK) {
        ts_set_err(out_err, ENOPROTOOPT);
        return TS_ERR;
    }

    if (getsockopt(s->fd, level, name, &val, &len) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }

    if (out_value != NULL) *out_value = val;
    return TS_OK;
}
#endif
