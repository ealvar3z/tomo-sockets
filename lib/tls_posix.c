#define _POSIX_C_SOURCE 200809L
#ifndef _WIN32
#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef yes
#pragma push_macro("yes")
#undef yes
#define TS_TLS_RESTORE_yes 1
#endif
#ifdef no
#pragma push_macro("no")
#undef no
#define TS_TLS_RESTORE_no 1
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef TS_TLS_RESTORE_yes
#pragma pop_macro("yes")
#undef TS_TLS_RESTORE_yes
#endif
#ifdef TS_TLS_RESTORE_no
#pragma pop_macro("no")
#undef TS_TLS_RESTORE_no
#endif

struct ts_tls {
    struct ts_sock *sock;
    SSL_CTX *ctx;
    SSL *ssl;
    int closed;
};

static int ts_tls_now_ms(int64_t *out_ms) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return TS_ERR;
    *out_ms = ((int64_t)ts.tv_sec * 1000) + ((int64_t)ts.tv_nsec / 1000000);
    return TS_OK;
}

static int ts_tls_wait_fd(int fd, short events, int timeout_ms, int *out_err) {
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

static int ts_tls_deadline_remaining(int64_t deadline_ms, int *out_timeout) {
    int64_t now_ms = 0;
    int64_t diff;

    if (ts_tls_now_ms(&now_ms) != TS_OK) return TS_ERR;
    diff = deadline_ms - now_ms;
    if (diff <= 0) {
        *out_timeout = 0;
        return TS_TIMEOUT;
    }
    if (diff > (int64_t)INT32_MAX) diff = INT32_MAX;
    *out_timeout = (int)diff;
    return TS_OK;
}

static int ts_tls_set_nonblocking(int fd, int enable, int *out_old_flags,
                                  int *out_err) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    if (out_old_flags != NULL) *out_old_flags = flags;

    if (enable) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) != 0) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    return TS_OK;
}

static int ts_tls_set_last_ssl_err(int *out_err) {
    unsigned long e = ERR_get_error();
    if (e == 0) {
        ts_set_err(out_err, EPROTO);
        return TS_ERR;
    }
    ts_set_err(out_err, (int)(e & 0x7fffffffUL));
    return TS_ERR;
}

static int ts_tls_apply_options(struct ts_tls *tls,
                                const struct ts_tls_options *opt,
                                int *out_err) {
    const struct ts_tls_options default_opt = {0};
    const struct ts_tls_options *cfg = opt ? opt : &default_opt;
    int verify_peer = cfg->verify_peer ? 1 : 0;
    int insecure_skip_verify = cfg->insecure_skip_verify ? 1 : 0;
    int rc;

    SSL_CTX_set_min_proto_version(tls->ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY);

    if (insecure_skip_verify) verify_peer = 0;
    if (verify_peer) SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER, NULL);
    else SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);

    if (verify_peer) {
        if (cfg->ca_file != NULL || cfg->ca_path != NULL) {
            if (SSL_CTX_load_verify_locations(tls->ctx, cfg->ca_file,
                                              cfg->ca_path)
                != 1) {
                return ts_tls_set_last_ssl_err(out_err);
            }
        } else {
            if (SSL_CTX_set_default_verify_paths(tls->ctx) != 1) {
                return ts_tls_set_last_ssl_err(out_err);
            }
        }
    }

    if (cfg->alpn_csv != NULL && cfg->alpn_csv[0] != '\0') {
        size_t in_len = strlen(cfg->alpn_csv);
        uint8_t *buf = malloc(in_len + 1);
        size_t out_len = 0;
        size_t i = 0;
        size_t start = 0;
        if (buf == NULL) {
            ts_set_err(out_err, ENOMEM);
            return TS_ERR;
        }

        while (i <= in_len) {
            if (cfg->alpn_csv[i] == ',' || cfg->alpn_csv[i] == '\0') {
                size_t len = i - start;
                if (len > 0) {
                    if (len > 255) {
                        free(buf);
                        ts_set_err(out_err, EINVAL);
                        return TS_ERR;
                    }
                    buf[out_len++] = (uint8_t)len;
                    memcpy(buf + out_len, cfg->alpn_csv + start, len);
                    out_len += len;
                }
                start = i + 1;
            }
            i++;
        }

        rc = SSL_CTX_set_alpn_protos(tls->ctx, buf, (unsigned int)out_len);
        free(buf);
        if (rc != 0) {
            return ts_tls_set_last_ssl_err(out_err);
        }
    }

    tls->ssl = SSL_new(tls->ctx);
    if (tls->ssl == NULL) return ts_tls_set_last_ssl_err(out_err);
    if (SSL_set_fd(tls->ssl, tls->sock->fd) != 1)
        return ts_tls_set_last_ssl_err(out_err);
    SSL_set_connect_state(tls->ssl);

    if (cfg->server_name != NULL && cfg->server_name[0] != '\0') {
        if (SSL_set_tlsext_host_name(tls->ssl, cfg->server_name) != 1) {
            return ts_tls_set_last_ssl_err(out_err);
        }
        if (verify_peer) {
            if (SSL_set1_host(tls->ssl, cfg->server_name) != 1) {
                return ts_tls_set_last_ssl_err(out_err);
            }
        }
    }

    return TS_OK;
}

int ts_tls_global_init(int *out_err) {
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return ts_tls_set_last_ssl_err(out_err);
    }
    return TS_OK;
}

int ts_tls_client_new(struct ts_tls **out_tls, struct ts_sock *sock,
                      const struct ts_tls_options *opt, int *out_err) {
    struct ts_tls *tls = NULL;
    int rc;

    if (out_tls == NULL || sock == NULL || sock->open == 0
        || sock->fd == TS_INVALID_FD) {
        ts_set_err(out_err, EINVAL);
        return TS_ERR;
    }

    rc = ts_tls_global_init(out_err);
    if (rc != TS_OK) return rc;

    tls = calloc(1, sizeof(*tls));
    if (tls == NULL) {
        ts_set_err(out_err, ENOMEM);
        return TS_ERR;
    }
    tls->sock = sock;
    tls->ctx = SSL_CTX_new(TLS_client_method());
    if (tls->ctx == NULL) {
        free(tls);
        return ts_tls_set_last_ssl_err(out_err);
    }

    rc = ts_tls_apply_options(tls, opt, out_err);
    if (rc != TS_OK) {
        ts_tls_free(tls);
        return rc;
    }

    *out_tls = tls;
    return TS_OK;
}

int ts_tls_handshake(struct ts_tls *tls, int timeout_ms, int *out_err) {
    int rc;
    int ssl_err;
    int old_flags = 0;
    int64_t deadline_ms = 0;
    int wait_ms = 0;

    if (tls == NULL || tls->ssl == NULL || tls->sock == NULL) {
        ts_set_err(out_err, EINVAL);
        return TS_ERR;
    }

    if (timeout_ms <= 0) {
        rc = SSL_do_handshake(tls->ssl);
        if (rc == 1) return TS_OK;
        ssl_err = SSL_get_error(tls->ssl, rc);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) return TS_CLOSED;
        return ts_tls_set_last_ssl_err(out_err);
    }

    if (ts_tls_now_ms(&deadline_ms) != TS_OK) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    deadline_ms += timeout_ms;

    if (ts_tls_set_nonblocking(tls->sock->fd, 1, &old_flags, out_err) != TS_OK)
        return TS_ERR;

    for (;;) {
        rc = SSL_do_handshake(tls->ssl);
        if (rc == 1) {
            (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
            return TS_OK;
        }

        ssl_err = SSL_get_error(tls->ssl, rc);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
            return TS_CLOSED;
        }
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            short events = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int rem_rc = ts_tls_deadline_remaining(deadline_ms, &wait_ms);
            if (rem_rc == TS_TIMEOUT) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                return TS_TIMEOUT;
            }
            if (rem_rc != TS_OK) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                ts_set_err(out_err, errno);
                return TS_ERR;
            }
            rc = ts_tls_wait_fd(tls->sock->fd, events, wait_ms, out_err);
            if (rc != TS_OK) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                return rc;
            }
            continue;
        }

        (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
        return ts_tls_set_last_ssl_err(out_err);
    }
}

static int ts_tls_io_with_timeout(struct ts_tls *tls, int timeout_ms,
                                  int is_send, const void *send_buf,
                                  size_t send_len, void *recv_buf,
                                  size_t recv_len, size_t *out_n,
                                  int *out_err) {
    int rc;
    int ssl_err;
    int old_flags = 0;
    int64_t deadline_ms = 0;
    int wait_ms = 0;

    if (tls == NULL || tls->ssl == NULL || tls->sock == NULL) {
        ts_set_err(out_err, EINVAL);
        return TS_ERR;
    }

    if (timeout_ms <= 0) {
        rc = is_send ? SSL_write(tls->ssl, send_buf, (int)send_len)
                     : SSL_read(tls->ssl, recv_buf, (int)recv_len);
        if (rc > 0) {
            if (out_n != NULL) *out_n = (size_t)rc;
            return TS_OK;
        }
        ssl_err = SSL_get_error(tls->ssl, rc);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) return TS_CLOSED;
        return ts_tls_set_last_ssl_err(out_err);
    }

    if (ts_tls_now_ms(&deadline_ms) != TS_OK) {
        ts_set_err(out_err, errno);
        return TS_ERR;
    }
    deadline_ms += timeout_ms;

    if (ts_tls_set_nonblocking(tls->sock->fd, 1, &old_flags, out_err) != TS_OK)
        return TS_ERR;

    for (;;) {
        rc = is_send ? SSL_write(tls->ssl, send_buf, (int)send_len)
                     : SSL_read(tls->ssl, recv_buf, (int)recv_len);
        if (rc > 0) {
            if (out_n != NULL) *out_n = (size_t)rc;
            (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
            return TS_OK;
        }

        ssl_err = SSL_get_error(tls->ssl, rc);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
            return TS_CLOSED;
        }
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            short events = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int rem_rc = ts_tls_deadline_remaining(deadline_ms, &wait_ms);
            if (rem_rc == TS_TIMEOUT) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                return TS_TIMEOUT;
            }
            if (rem_rc != TS_OK) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                ts_set_err(out_err, errno);
                return TS_ERR;
            }
            rc = ts_tls_wait_fd(tls->sock->fd, events, wait_ms, out_err);
            if (rc != TS_OK) {
                (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
                return rc;
            }
            continue;
        }

        (void)fcntl(tls->sock->fd, F_SETFL, old_flags);
        return ts_tls_set_last_ssl_err(out_err);
    }
}

int ts_tls_send(struct ts_tls *tls, const void *buf, size_t len, int timeout_ms,
                size_t *out_sent, int *out_err) {
    return ts_tls_io_with_timeout(tls, timeout_ms, 1, buf, len, NULL, 0,
                                  out_sent, out_err);
}

int ts_tls_recv(struct ts_tls *tls, void *buf, size_t len, int timeout_ms,
                size_t *out_got, int *out_err) {
    return ts_tls_io_with_timeout(tls, timeout_ms, 0, NULL, 0, buf, len,
                                  out_got, out_err);
}

int ts_tls_close(struct ts_tls *tls, int *out_err) {
    int rc = TS_OK;
    int ssl_rc;

    if (tls == NULL) return TS_OK;
    if (tls->closed) return TS_OK;

    if (tls->ssl != NULL) {
        ssl_rc = SSL_shutdown(tls->ssl);
        if (ssl_rc < 0) {
            rc = ts_tls_set_last_ssl_err(out_err);
        }
    }

    if (tls->sock != NULL && tls->sock->open) {
        int sock_rc = ts_sock_close(tls->sock, out_err);
        if (rc == TS_OK) rc = sock_rc;
    }

    tls->closed = 1;
    return rc;
}

void ts_tls_free(struct ts_tls *tls) {
    if (tls == NULL) return;
    if (tls->ssl != NULL) SSL_free(tls->ssl);
    if (tls->ctx != NULL) SSL_CTX_free(tls->ctx);
    free(tls);
}

int ts_tls_peer_cert_subject(struct ts_tls *tls, char *out, size_t out_len,
                             int *out_err) {
    X509 *cert;
    X509_NAME *subject;

    if (tls == NULL || tls->ssl == NULL || out == NULL || out_len == 0) {
        ts_set_err(out_err, EINVAL);
        return TS_ERR;
    }

    cert = SSL_get1_peer_certificate(tls->ssl);
    if (cert == NULL) {
        ts_set_err(out_err, ENOENT);
        return TS_ERR;
    }

    subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        X509_free(cert);
        ts_set_err(out_err, EPROTO);
        return TS_ERR;
    }

    if (X509_NAME_oneline(subject, out, (int)out_len) == NULL) {
        X509_free(cert);
        return ts_tls_set_last_ssl_err(out_err);
    }

    X509_free(cert);
    return TS_OK;
}

int ts_tls_selected_alpn(struct ts_tls *tls, char *out, size_t out_len,
                         int *out_err) {
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;

    if (tls == NULL || tls->ssl == NULL || out == NULL || out_len == 0) {
        ts_set_err(out_err, EINVAL);
        return TS_ERR;
    }

    SSL_get0_alpn_selected(tls->ssl, &alpn, &alpn_len);
    if (alpn == NULL || alpn_len == 0) {
        ts_set_err(out_err, ENOENT);
        return TS_ERR;
    }

    if ((size_t)alpn_len >= out_len) {
        ts_set_err(out_err, ENOBUFS);
        return TS_ERR;
    }

    memcpy(out, alpn, alpn_len);
    out[alpn_len] = '\0';
    return TS_OK;
}

const char *ts_tls_strerror(int err) {
    static char buf[256];
    const char *reason = ERR_reason_error_string((unsigned long)(uint32_t)err);
    if (reason != NULL) {
        ERR_error_string_n((unsigned long)(uint32_t)err, buf, sizeof(buf));
        return buf;
    }
    return strerror(err);
}
#endif
