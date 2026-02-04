#include "sockets.h"

#include <errno.h>
#include <string.h>

int ts_addr_resolve(const char *host, const char *service, int family, int socktype, struct ts_addr *out_addr,
                    int *out_err) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;

    err = getaddrinfo(host, service, &hints, &res);
    if (err != 0) {
        ts_set_err(out_err, err);
        return TS_ERR;
    }

    if (res == NULL) {
        ts_set_err(out_err, EAI_FAIL);
        return TS_ERR;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    memcpy(&out_addr->ss, res->ai_addr, res->ai_addrlen);
    out_addr->len = (socklen_t)res->ai_addrlen;
    out_addr->family = res->ai_family;

    freeaddrinfo(res);
    return TS_OK;
}

int ts_addr_to_string(const struct ts_addr *addr, char *host, size_t host_len, char *service, size_t service_len,
                      int *out_err) {
    int err;

    err = getnameinfo((const struct sockaddr *)&addr->ss, addr->len, host, (socklen_t)host_len, service,
                      (socklen_t)service_len, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err != 0) {
        ts_set_err(out_err, err);
        return TS_ERR;
    }

    return TS_OK;
}

const char *ts_addr_strerror(int err) { return gai_strerror(err); }
