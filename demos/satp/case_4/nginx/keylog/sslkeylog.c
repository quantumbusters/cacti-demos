#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_st SSL;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef SSL_CTX *(*ctx_new_fn)(const SSL_METHOD *);
typedef SSL_CTX *(*ctx_new_ex_fn)(OSSL_LIB_CTX *, const char *, const SSL_METHOD *);
typedef void (*set_keylog_fn)(SSL_CTX *, void (*)(const SSL *, const char *));

static void write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        data += written;
        length -= (size_t) written;
    }
}

static void case4_keylog_callback(const SSL *ssl, const char *line) {
    (void) ssl;
    const char *path = getenv("SSLKEYLOGFILE");
    if (path == NULL || path[0] == '\0' || line == NULL) {
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return;
    }

    if (flock(fd, LOCK_EX) == 0) {
        write_all(fd, line, strlen(line));
        write_all(fd, "\n", 1);
        (void) flock(fd, LOCK_UN);
    }
    (void) close(fd);
}

static void register_callback(SSL_CTX *ctx) {
    if (ctx == NULL) {
        return;
    }
    set_keylog_fn setter =
        (set_keylog_fn) dlsym(RTLD_NEXT, "SSL_CTX_set_keylog_callback");
    if (setter != NULL) {
        setter(ctx, case4_keylog_callback);
    }
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
    ctx_new_fn real_new = (ctx_new_fn) dlsym(RTLD_NEXT, "SSL_CTX_new");
    if (real_new == NULL) {
        return NULL;
    }
    SSL_CTX *ctx = real_new(method);
    register_callback(ctx);
    return ctx;
}

SSL_CTX *SSL_CTX_new_ex(
    OSSL_LIB_CTX *libctx,
    const char *propq,
    const SSL_METHOD *method
) {
    ctx_new_ex_fn real_new =
        (ctx_new_ex_fn) dlsym(RTLD_NEXT, "SSL_CTX_new_ex");
    if (real_new == NULL) {
        return NULL;
    }
    SSL_CTX *ctx = real_new(libctx, propq, method);
    register_callback(ctx);
    return ctx;
}

void SSL_CTX_set_keylog_callback(
    SSL_CTX *ctx,
    void (*callback)(const SSL *, const char *)
) {
    (void) callback;
    set_keylog_fn real_setter =
        (set_keylog_fn) dlsym(RTLD_NEXT, "SSL_CTX_set_keylog_callback");
    if (real_setter != NULL) {
        real_setter(ctx, case4_keylog_callback);
    }
}
