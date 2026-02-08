#ifdef _WIN32
#include "tls.h"

#include <winsock2.h>

struct ts_tls {};

int ts_tls_global_init(int *out_err) {
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_client_new(struct ts_tls **out_tls, struct ts_sock *sock,
                      const struct ts_tls_options *opt, int *out_err) {
    (void)out_tls;
    (void)sock;
    (void)opt;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_handshake(struct ts_tls *tls, int timeout_ms, int *out_err) {
    (void)tls;
    (void)timeout_ms;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_send(struct ts_tls *tls, const void *buf, size_t len, int timeout_ms,
                size_t *out_sent, int *out_err) {
    (void)tls;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    (void)out_sent;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_recv(struct ts_tls *tls, void *buf, size_t len, int timeout_ms,
                size_t *out_got, int *out_err) {
    (void)tls;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    (void)out_got;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_close(struct ts_tls *tls, int *out_err) {
    (void)tls;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

void ts_tls_free(struct ts_tls *tls) {
    (void)tls;
}

int ts_tls_peer_cert_subject(struct ts_tls *tls, char *out, size_t out_len,
                             int *out_err) {
    (void)tls;
    (void)out;
    (void)out_len;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

int ts_tls_selected_alpn(struct ts_tls *tls, char *out, size_t out_len,
                         int *out_err) {
    (void)tls;
    (void)out;
    (void)out_len;
    ts_set_err(out_err, WSAEOPNOTSUPP);
    return TS_ERR;
}

const char *ts_tls_strerror(int err) {
    (void)err;
    return "TLS unsupported on Windows in this build";
}
#endif
