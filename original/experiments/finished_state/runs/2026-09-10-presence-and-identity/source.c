/*
 * Compare three cache-update points for pq_cert_available:
 *   1. the CertificateEntry extension parse callback;
 *   2. after a valid CertificateVerify has been processed;
 *   3. after SSL_is_init_finished() becomes true.
 *
 * This is a controlled test harness.  Its post-CertificateVerify failure is
 * produced by decrypting the server Finished record with keylog material,
 * changing one verify_data byte and re-encrypting it with a valid AEAD tag.
 * It is harness-enabled corruption, not a network attack.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/x509_vfy.h>

#define PQ_CERT_AVAILABLE 0xFDFD
#define PRIOR_COMMITMENT 86400U
#define MAX_STEPS 1000

static const char *const SERVER_CERT = "../testbed/server.crt";
static const char *const SERVER_KEY = "../testbed/server.key";
static const char *const CA_CERT = "../testbed/ca.crt";

struct cache {
    uint32_t parser_time;
    uint32_t after_cv;
    uint32_t after_finished;
};

struct run {
    struct cache *cache;
    uint32_t value;
    uint32_t received_value;
    int send_extension;
    unsigned char wire_value[4];
    int events;
    int parse_order;
    int cv_message_order;
    int cv_processed_order;
    int injection_order;
    int finished_message_order;
    int init_finished_order;
    int terminal_order;
    int cv_message_seen;
    int finished_message_seen;
    int inject_finished;
    int finished_corrupted;
    int client_done;
    int server_done;
    int client_failed;
    int client_error;
    int client_reason;
    int peer_is_mldsa65;
    char peer_key_name[80];
    unsigned char server_handshake_secret[32];
    unsigned char server_handshake_key[16];
    unsigned char server_handshake_iv[12];
    uint64_t server_record_sequence;
    int have_server_handshake_secret;
    int have_server_handshake_keys;
};

/* ponytail: one experiment runs at a time; use SSL ex_data if concurrency is added. */
static struct run *active_run;

enum scenario {
    COMMIT_SUCCESS,
    OMIT_EXTENSION_SUCCESS,
    WITHDRAW_INVALID_CHAIN,
    WITHDRAW_AFTER_CV,
    WITHDRAW_SUCCESS
};

static void fail_ssl(const char *what)
{
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "FAIL: %s\n", what);
    exit(2);
}

static void print_cache(const char *label, const struct cache *cache)
{
    printf("  cache_%s parser=%u after_cv=%u after_finished=%u\n",
           label, cache->parser_time, cache->after_cv,
           cache->after_finished);
}

static int server_add(SSL *ssl, unsigned int type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *alert, void *arg)
{
    struct run *run = arg;
    (void)ssl;
    (void)type;
    (void)x;
    (void)alert;

    if (!run->send_extension || !(context & SSL_EXT_TLS1_3_CERTIFICATE) || chainidx != 0)
        return 0;
    *out = run->wire_value;
    *outlen = sizeof(run->wire_value);
    return 1;
}

static int client_add(SSL *ssl, unsigned int type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *alert, void *arg)
{
    (void)ssl;
    (void)type;
    (void)x;
    (void)chainidx;
    (void)alert;
    (void)arg;

    if (!(context & SSL_EXT_CLIENT_HELLO))
        return 0;
    *out = NULL;
    *outlen = 0;
    return 1;
}

static int client_parse(SSL *ssl, unsigned int type, unsigned int context,
                        const unsigned char *in, size_t inlen, X509 *x,
                        size_t chainidx, int *alert, void *arg)
{
    struct run *run = arg;
    EVP_PKEY *key;
    uint32_t value;
    const char *name;
    (void)ssl;
    (void)type;
    (void)alert;

    if (!(context & SSL_EXT_TLS1_3_CERTIFICATE) || chainidx != 0)
        return 1;
    if (inlen != 4)
        return 0;

    value = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
          | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    run->parse_order = ++run->events;
    run->received_value = value;
    run->cache->parser_time = value;

    key = x == NULL ? NULL : X509_get0_pubkey(x);
    name = key == NULL ? NULL : EVP_PKEY_get0_type_name(key);
    snprintf(run->peer_key_name, sizeof(run->peer_key_name), "%s",
             name == NULL ? "missing" : name);
    run->peer_is_mldsa65 = key != NULL && EVP_PKEY_is_a(key, "ML-DSA-65");
    return 1;
}

static void message_cb(int write_p, int version, int content_type,
                       const void *buf, size_t len, SSL *ssl, void *arg)
{
    struct run *run = arg;
    const unsigned char *message = buf;
    (void)version;
    (void)ssl;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len == 0)
        return;
    if (message[0] == SSL3_MT_CERTIFICATE_VERIFY && !run->cv_message_seen) {
        run->cv_message_seen = 1;
        run->cv_message_order = ++run->events;
    } else if (message[0] == SSL3_MT_FINISHED
               && !run->finished_message_seen) {
        run->finished_message_seen = 1;
        run->finished_message_order = ++run->events;
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void keylog_cb(const SSL *ssl, const char *line)
{
    static const char label[] = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
    const char *hex;
    size_t hex_len;
    (void)ssl;

    if (active_run == NULL || strncmp(line, label, sizeof(label) - 1) != 0)
        return;
    hex = strrchr(line, ' ');
    if (hex == NULL)
        return;
    hex++;
    hex_len = strlen(hex);
    if (hex_len != sizeof(active_run->server_handshake_secret) * 2)
        return;
    for (size_t i = 0; i < sizeof(active_run->server_handshake_secret); i++) {
        int high = hex_nibble(hex[2 * i]);
        int low = hex_nibble(hex[2 * i + 1]);
        if (high < 0 || low < 0)
            return;
        active_run->server_handshake_secret[i]
            = (unsigned char)((high << 4) | low);
    }
    active_run->have_server_handshake_secret = 1;
}

static void hkdf_expand_label(const unsigned char *secret, const char *label,
                              unsigned char *out, size_t outlen)
{
    static const char prefix[] = "tls13 ";
    EVP_PKEY_CTX *ctx;
    unsigned char info[32];
    size_t label_len = strlen(label);
    size_t full_label_len = sizeof(prefix) - 1 + label_len;
    size_t info_len = 4 + full_label_len;
    size_t derived = outlen;

    if (full_label_len > 255 || info_len > sizeof(info))
        fail_ssl("construct HKDF label");
    info[0] = (unsigned char)(outlen >> 8);
    info[1] = (unsigned char)outlen;
    info[2] = (unsigned char)full_label_len;
    memcpy(info + 3, prefix, sizeof(prefix) - 1);
    memcpy(info + 3 + sizeof(prefix) - 1, label, label_len);
    info[3 + full_label_len] = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_CTX_set_hkdf_mode(ctx,
                                      EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
        || EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0
        || EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, 32) <= 0
        || EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0
        || EVP_PKEY_derive(ctx, out, &derived) <= 0 || derived != outlen) {
        EVP_PKEY_CTX_free(ctx);
        fail_ssl("derive TLS 1.3 traffic key");
    }
    EVP_PKEY_CTX_free(ctx);
}

static void make_nonce(const struct run *run, unsigned char nonce[12])
{
    uint64_t sequence = run->server_record_sequence;

    memcpy(nonce, run->server_handshake_iv, 12);
    for (size_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= (unsigned char)sequence;
        sequence >>= 8;
    }
}

static void gcm_decrypt(const struct run *run, const unsigned char header[5],
                        const unsigned char *ciphertext, size_t ciphertext_len,
                        const unsigned char tag[16], unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[12];
    unsigned char tag_copy[16];
    int n;
    int total = 0;

    make_nonce(run, nonce);
    memcpy(tag_copy, tag, sizeof(tag_copy));
    if (ctx == NULL
        || EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               sizeof(nonce), NULL) != 1
        || EVP_DecryptInit_ex(ctx, NULL, NULL, run->server_handshake_key,
                              nonce) != 1
        || EVP_DecryptUpdate(ctx, NULL, &n, header, 5) != 1
        || EVP_DecryptUpdate(ctx, plaintext, &n, ciphertext,
                             (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fail_ssl("decrypt server handshake record");
    }
    total = n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_copy) != 1
        || EVP_DecryptFinal_ex(ctx, plaintext + total, &n) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fail_ssl("authenticate server handshake record");
    }
    EVP_CIPHER_CTX_free(ctx);
}

static void gcm_encrypt(const struct run *run, const unsigned char header[5],
                        const unsigned char *plaintext, size_t plaintext_len,
                        unsigned char *ciphertext, unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[12];
    int n;
    int total = 0;

    make_nonce(run, nonce);
    if (ctx == NULL
        || EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(ctx, NULL, NULL, run->server_handshake_key,
                              nonce) != 1
        || EVP_EncryptUpdate(ctx, NULL, &n, header, 5) != 1
        || EVP_EncryptUpdate(ctx, ciphertext, &n, plaintext,
                             (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fail_ssl("re-encrypt server Finished record");
    }
    total = n;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &n) != 1
        || (size_t)(total + n) != plaintext_len
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fail_ssl("finish re-encrypting server Finished record");
    }
    EVP_CIPHER_CTX_free(ctx);
}

static void maybe_corrupt_finished(struct run *run, unsigned char *record,
                                   size_t record_len)
{
    unsigned char *plaintext;
    size_t ciphertext_len;
    size_t content_len;
    int changed = 0;

    if (!run->inject_finished || run->finished_corrupted
        || record[0] != SSL3_RT_APPLICATION_DATA)
        return;
    if (!run->have_server_handshake_secret || record_len < 5 + 16)
        fail_ssl("server handshake secret unavailable before encrypted record");
    if (!run->have_server_handshake_keys) {
        hkdf_expand_label(run->server_handshake_secret, "key",
                          run->server_handshake_key,
                          sizeof(run->server_handshake_key));
        hkdf_expand_label(run->server_handshake_secret, "iv",
                          run->server_handshake_iv,
                          sizeof(run->server_handshake_iv));
        run->have_server_handshake_keys = 1;
    }

    ciphertext_len = record_len - 5 - 16;
    plaintext = malloc(ciphertext_len);
    if (plaintext == NULL)
        fail_ssl("allocate decrypted record");
    gcm_decrypt(run, record, record + 5, ciphertext_len,
                record + 5 + ciphertext_len, plaintext);

    content_len = ciphertext_len;
    while (content_len > 0 && plaintext[content_len - 1] == 0)
        content_len--;
    if (content_len == 0)
        fail_ssl("empty TLSInnerPlaintext");
    if (plaintext[--content_len] == SSL3_RT_HANDSHAKE
        && run->cv_processed_order && content_len > 4
        && plaintext[0] == SSL3_MT_FINISHED) {
        size_t message_len = 4U + ((size_t)plaintext[1] << 16)
                           + ((size_t)plaintext[2] << 8)
                           + (size_t)plaintext[3];
        if (message_len == content_len) {
            plaintext[4] ^= 1;
            run->finished_corrupted = 1;
            run->injection_order = ++run->events;
            changed = 1;
        }
    }
    if (changed)
        gcm_encrypt(run, record, plaintext, ciphertext_len, record + 5,
                    record + 5 + ciphertext_len);
    free(plaintext);
    run->server_record_sequence++;
}

/* Copy one complete TLS record; only the selected Finished case changes data. */
static int pump_one_record(SSL *from, SSL *to, struct run *run,
                           int from_server)
{
    BIO *out = SSL_get_wbio(from);
    BIO *in = SSL_get_rbio(to);
    char *pending_data = NULL;
    unsigned char *copy;
    long pending = BIO_get_mem_data(out, &pending_data);
    size_t record_len;
    int n;

    if (pending < 5)
        return 0;
    record_len = 5U + ((size_t)(unsigned char)pending_data[3] << 8)
                     + (size_t)(unsigned char)pending_data[4];
    if ((size_t)pending < record_len)
        return 0;

    copy = malloc(record_len);
    if (copy == NULL)
        fail_ssl("allocate record copy");
    n = BIO_read(out, copy, (int)record_len);
    if (n != (int)record_len) {
        free(copy);
        fail_ssl("read in-memory TLS record");
    }
    if (from_server)
        maybe_corrupt_finished(run, copy, record_len);
    if (BIO_write(in, copy, n) != n) {
        free(copy);
        fail_ssl("write in-memory TLS record");
    }
    free(copy);
    return 1;
}

static int wants_io(SSL *ssl, int result, int *error)
{
    *error = SSL_get_error(ssl, result);
    return *error == SSL_ERROR_WANT_READ || *error == SSL_ERROR_WANT_WRITE;
}

static int cache_is(const struct cache *cache, uint32_t parser,
                    uint32_t after_cv, uint32_t after_finished)
{
    return cache->parser_time == parser && cache->after_cv == after_cv
        && cache->after_finished == after_finished;
}

static int expected(enum scenario scenario, const struct run *run,
                    long verify_result)
{
    const struct cache *cache = run->cache;
    int common = run->parse_order > 0 && run->peer_is_mldsa65
              && run->terminal_order > run->parse_order;

    switch (scenario) {
    case COMMIT_SUCCESS:
        return common && run->client_done && run->server_done
            && run->cv_processed_order > run->parse_order
            && run->finished_message_order > run->cv_message_order
            && run->init_finished_order > run->finished_message_order
            && verify_result == X509_V_OK
            && cache_is(cache, PRIOR_COMMITMENT, PRIOR_COMMITMENT,
                        PRIOR_COMMITMENT);
    case OMIT_EXTENSION_SUCCESS:
        return run->parse_order == 0 && run->client_done && run->server_done
            && run->peer_is_mldsa65 && run->cv_processed_order > 0
            && run->init_finished_order > run->finished_message_order
            && verify_result == X509_V_OK
            && cache_is(cache, PRIOR_COMMITMENT, PRIOR_COMMITMENT, PRIOR_COMMITMENT);
    case WITHDRAW_INVALID_CHAIN:
        return common && run->client_failed && !run->cv_message_seen
            && !run->finished_message_seen && !run->client_done
            && verify_result != X509_V_OK
            && cache_is(cache, 0, PRIOR_COMMITMENT, PRIOR_COMMITMENT);
    case WITHDRAW_AFTER_CV:
        return common && run->client_failed && run->finished_corrupted
            && run->cv_processed_order > run->parse_order
            && run->injection_order > run->cv_processed_order
            && run->finished_message_order > run->injection_order
            && !run->init_finished_order && !run->client_done
            && run->client_error == SSL_ERROR_SSL
            && run->client_reason == SSL_R_DIGEST_CHECK_FAILED
            && verify_result == X509_V_OK
            && cache_is(cache, 0, 0, PRIOR_COMMITMENT);
    case WITHDRAW_SUCCESS:
        return common && run->client_done && run->server_done
            && run->cv_processed_order > run->parse_order
            && run->finished_message_order > run->cv_message_order
            && run->init_finished_order > run->finished_message_order
            && verify_result == X509_V_OK && cache_is(cache, 0, 0, 0);
    }
    return 0;
}

static int run_case(const char *label, enum scenario scenario,
                    struct cache *cache, uint32_t value, int trust_ca,
                    int inject_finished)
{
    struct cache before = *cache;
    struct run run = {
        .cache = cache,
        .value = value,
        .send_extension = scenario != OMIT_EXTENSION_SUCCESS,
        .inject_finished = inject_finished
    };
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *server_read = NULL;
    BIO *server_write = NULL;
    BIO *client_read = NULL;
    BIO *client_write = NULL;
    long verify_result;
    int pass;

    run.wire_value[0] = (unsigned char)(value >> 24);
    run.wire_value[1] = (unsigned char)(value >> 16);
    run.wire_value[2] = (unsigned char)(value >> 8);
    run.wire_value[3] = (unsigned char)value;

    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (server_ctx == NULL || client_ctx == NULL)
        fail_ssl("SSL_CTX_new");
    if (!SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(server_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_ciphersuites(server_ctx, "TLS_AES_128_GCM_SHA256")
        || !SSL_CTX_set_ciphersuites(client_ctx, "TLS_AES_128_GCM_SHA256"))
        fail_ssl("configure TLS 1.3");
    if (SSL_CTX_use_certificate_chain_file(server_ctx, SERVER_CERT) != 1
        || SSL_CTX_use_PrivateKey_file(server_ctx, SERVER_KEY,
                                       SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(server_ctx) != 1)
        fail_ssl("load ML-DSA-65 server credential");

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    if (trust_ca && SSL_CTX_load_verify_locations(client_ctx, CA_CERT, NULL) != 1)
        fail_ssl("load test CA");
    SSL_CTX_set_msg_callback(client_ctx, message_cb);
    SSL_CTX_set_msg_callback_arg(client_ctx, &run);
    SSL_CTX_set_keylog_callback(server_ctx, keylog_cb);

    if (SSL_CTX_add_custom_ext(server_ctx, PQ_CERT_AVAILABLE,
                               SSL_EXT_CLIENT_HELLO
                               | SSL_EXT_TLS1_3_CERTIFICATE,
                               server_add, NULL, &run, NULL, NULL) != 1
        || SSL_CTX_add_custom_ext(client_ctx, PQ_CERT_AVAILABLE,
                                  SSL_EXT_CLIENT_HELLO
                                  | SSL_EXT_TLS1_3_CERTIFICATE,
                                  client_add, NULL, NULL,
                                  client_parse, &run) != 1)
        fail_ssl("register pq_cert_available");

    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    server_read = BIO_new(BIO_s_mem());
    server_write = BIO_new(BIO_s_mem());
    client_read = BIO_new(BIO_s_mem());
    client_write = BIO_new(BIO_s_mem());
    if (server == NULL || client == NULL || server_read == NULL
        || server_write == NULL || client_read == NULL || client_write == NULL)
        fail_ssl("allocate SSL objects and memory BIOs");
    BIO_set_mem_eof_return(server_read, -1);
    BIO_set_mem_eof_return(client_read, -1);
    SSL_set_bio(server, server_read, server_write);
    SSL_set_bio(client, client_read, client_write);
    SSL_set_accept_state(server);
    if (!SSL_set1_host(client, "localhost") || !SSL_set_tlsext_host_name(client, "localhost"))
        fail_ssl("configure reference identity");
    SSL_set_connect_state(client);
    active_run = &run;

    for (int step = 0; step < MAX_STEPS && !run.client_failed
                                      && !(run.client_done && run.server_done);
         step++) {
        int result;
        int error = SSL_ERROR_NONE;

        if (!run.client_done) {
            int cv_before = run.cv_message_seen;
            result = SSL_do_handshake(client);
            if (result == 1) {
                run.client_done = 1;
            } else if (!wants_io(client, result, &error)) {
                run.client_failed = 1;
                run.client_error = error;
                run.client_reason = ERR_GET_REASON(ERR_peek_last_error());
            }

            if (!cv_before && run.cv_message_seen && !run.client_failed) {
                run.cv_processed_order = ++run.events;
                if (run.parse_order)
                    run.cache->after_cv = run.received_value;
            }
            if (!run.init_finished_order && SSL_is_init_finished(client)) {
                run.init_finished_order = ++run.events;
                if (run.parse_order)
                    run.cache->after_finished = run.received_value;
            }
        }

        while (pump_one_record(client, server, &run, 0))
            ;

        if (!run.server_done && !run.client_failed) {
            result = SSL_do_handshake(server);
            if (result == 1) {
                run.server_done = 1;
            } else if (!wants_io(server, result, &error)) {
                run.client_failed = 1;
                run.client_error = error;
            }
        }

        (void)pump_one_record(server, client, &run, 1);
    }

    active_run = NULL;
    run.terminal_order = ++run.events;
    verify_result = SSL_get_verify_result(client);
    if (!run.parse_order && run.client_done) {
        X509 *peer = SSL_get0_peer_certificate(client);
        EVP_PKEY *key = peer == NULL ? NULL : X509_get0_pubkey(peer);
        run.peer_is_mldsa65 = key != NULL && EVP_PKEY_is_a(key, "ML-DSA-65");
        snprintf(run.peer_key_name, sizeof(run.peer_key_name), "%s",
                 key == NULL ? "missing" : EVP_PKEY_get0_type_name(key));
    }
    pass = expected(scenario, &run, verify_result);

    printf("\nCASE %s\n", label);
    print_cache("before", &before);
    printf("  events parse=%d cv_message=%d cv_processed=%d injection=%d "
           "finished_message=%d init_finished=%d terminal=%d\n",
           run.parse_order, run.cv_message_order, run.cv_processed_order,
           run.injection_order, run.finished_message_order,
           run.init_finished_order, run.terminal_order);
    printf("  handshake client=%s server=%s finished_corrupted=%s "
           "ssl_error=%d ssl_reason=%d\n",
           run.client_done ? "complete" : run.client_failed ? "failed" : "stalled",
           run.server_done ? "complete" : "incomplete",
           run.finished_corrupted ? "yes" : "no", run.client_error,
           run.client_reason);
    printf("  verification=%ld (%s) peer_key=%s\n", verify_result,
           X509_verify_cert_error_string(verify_result), run.peer_key_name);
    print_cache("after", cache);
    printf("  CASE %s\n", pass ? "PASS" : "FAIL");

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    ERR_clear_error();
    return pass;
}

int main(void)
{
    struct cache cache = { 0, 0, 0 };

    printf("OpenSSL runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Credential: existing testbed ML-DSA-65 server chain\n");

    if (!run_case("1 commit succeeds", COMMIT_SUCCESS, &cache,
                  PRIOR_COMMITMENT, 1, 0)
        || !run_case("2 extension omitted", OMIT_EXTENSION_SUCCESS, &cache, 0, 1, 0)
        || !run_case("3 zero withdrawal with invalid chain",
                     WITHDRAW_INVALID_CHAIN, &cache, 0, 0, 0)
        || !run_case("4 zero withdrawal with invalid Finished after CertificateVerify",
                     WITHDRAW_AFTER_CV, &cache, 0, 1, 1)
        || !run_case("5 zero withdrawal succeeds", WITHDRAW_SUCCESS,
                     &cache, 0, 1, 0)) {
        printf("\nFAIL: a control, ordering check or cache-state assertion failed\n");
        return 1;
    }

    printf("\nPASS: only the SSL_is_init_finished policy preserved the prior "
           "commitment across both failed handshakes\n");
    return 0;
}
