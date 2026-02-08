#pragma once

#include <stddef.h>

#include "sockets.h"

struct ts_tls;

struct ts_tls_options {
    const char *server_name;
    int verify_peer;
    int insecure_skip_verify;
    const char *ca_file;
    const char *ca_path;
    const char *alpn_csv;
};

int ts_tls_global_init(int *out_err);

int ts_tls_client_new(struct ts_tls **out_tls, struct ts_sock *sock,
                      const struct ts_tls_options *opt, int *out_err);
int ts_tls_handshake(struct ts_tls *tls, int timeout_ms, int *out_err);
int ts_tls_send(struct ts_tls *tls, const void *buf, size_t len, int timeout_ms,
                size_t *out_sent, int *out_err);
int ts_tls_recv(struct ts_tls *tls, void *buf, size_t len, int timeout_ms,
                size_t *out_got, int *out_err);
int ts_tls_close(struct ts_tls *tls, int *out_err);
void ts_tls_free(struct ts_tls *tls);

int ts_tls_peer_cert_subject(struct ts_tls *tls, char *out, size_t out_len,
                             int *out_err);
int ts_tls_selected_alpn(struct ts_tls *tls, char *out, size_t out_len,
                         int *out_err);

const char *ts_tls_strerror(int err);
