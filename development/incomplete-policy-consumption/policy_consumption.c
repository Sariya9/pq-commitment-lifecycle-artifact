/* Bounded follow-up: consume each shadow cache through a real TLS offer.
 * Original lifecycle code and records remain unchanged. The classical peer
 * is a controlled policy probe, not a compliant post-withdrawal deployment.
 */
#define main retained_overlap_main
#include "overlap_state.c"
#undef main

static const char *classical_cert, *classical_key, *classical_ca;
struct offer_observation { int calls, count, classical; };

static int inspect_offer(SSL *ssl, int *alert, void *arg) {
    struct offer_observation *o = arg;
    const unsigned char *data = NULL;
    size_t length = 0;
    (void)alert;
    CHECK(SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms,
                                   &data, &length));
    CHECK(length >= 2 && (((size_t)data[0] << 8) | data[1]) == length - 2);
    CHECK((length - 2) % 2 == 0);
    o->calls++;
    printf(" sigalgs=");
    for (size_t i = 2; i < length; i += 2) {
        unsigned int scheme = ((unsigned int)data[i] << 8) | data[i + 1];
        printf("%s%04x", i == 2 ? "" : ":", scheme);
        o->count++;
        if (scheme == 0x0403) o->classical = 1;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void consume(const char *label, uint32_t cache, int classical, int accept) {
    struct store local = {cache, cache};
    struct pair p;
    struct offer_observation offer = {0};
    init(&p, COMMIT, 1, &local);
    CHECK(SSL_set1_sigalgs_list(p.client, cache ? "mldsa65" :
                              "mldsa65:ecdsa_secp256r1_sha256"));
    SSL_CTX_set_client_hello_cb(p.sc, inspect_offer, &offer);
    if (classical) {
        p.send_extension = 0;
        CHECK(SSL_use_certificate_chain_file(p.server, classical_cert));
        CHECK(SSL_use_PrivateKey_file(p.server, classical_key, SSL_FILETYPE_PEM));
        CHECK(SSL_check_private_key(p.server));
        CHECK(SSL_CTX_load_verify_locations(p.cc, classical_ca, NULL));
        CHECK(SSL_set1_verify_cert_store(p.client, SSL_CTX_get_cert_store(p.cc)));
    }
    printf("PROBE %s cache=%u peer=%s", label, cache, classical ? "ECDSA" : "ML-DSA-65");
    drive(&p, 0);
    CHECK(offer.calls == 1 && offer.count == (cache ? 1 : 2));
    CHECK(offer.classical == !cache);
    if (accept) {
        CHECK(!p.failed && p.client_done && p.server_done);
        CHECK(SSL_version(p.client) == TLS1_3_VERSION && !SSL_session_reused(p.client));
        CHECK(SSL_get_verify_result(p.client) == X509_V_OK);
        X509 *cert = SSL_get0_peer_certificate(p.client);
        EVP_PKEY *key = cert ? X509_get0_pubkey(cert) : NULL;
        CHECK(key && EVP_PKEY_is_a(key, classical ? "EC" : "ML-DSA-65"));
        printf(" result=ACCEPT verified=yes\n");
    } else {
        CHECK(classical && cache && p.failed && !p.client_done && !p.server_done);
        CHECK(ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM);
        printf(" result=REJECT reason=no-suitable-signature-algorithm\n");
    }
    free_pair(&p);
}

static void follow_loss(void) {
    struct store s = {0, 0};
    struct pair a, b;
    init(&a, 0, 1, &s); drive(&a, 1); CHECK(paused(&a));
    init(&b, COMMIT, 1, &s); drive(&b, 0); commit(&b, &s);
    CHECK(paused(&a));
    uint32_t snapshot = a.snapshot;
    free_pair(&a); s.restore = snapshot; free_pair(&b);
    CHECK(s.preserve == COMMIT && s.restore == 0);
    consume("loss-preserve", s.preserve, 1, 0);
    consume("loss-restore", s.restore, 1, 1);
    consume("loss-preserve-PQ", s.preserve, 0, 1);
    consume("loss-restore-PQ", s.restore, 0, 1);
}

static void follow_withdrawal(void) {
    struct store s = {0, 0};
    struct pair seed, a, b;
    init(&seed, COMMIT, 1, &s); drive(&seed, 0); commit(&seed, &s); free_pair(&seed);
    init(&a, 0, 1, &s); drive(&a, 1); CHECK(paused(&a));
    init(&b, 0, 1, &s); drive(&b, 0); commit(&b, &s);
    CHECK(paused(&a));
    uint32_t snapshot = a.snapshot;
    free_pair(&a); s.restore = snapshot; free_pair(&b);
    CHECK(s.preserve == 0 && s.restore == COMMIT);
    consume("withdraw-preserve", s.preserve, 1, 1);
    consume("withdraw-restore", s.restore, 1, 0);
    consume("withdraw-preserve-PQ", s.preserve, 0, 1);
    consume("withdraw-restore-PQ", s.restore, 0, 1);
}

static void active_failure(int wrong_identity) {
    struct store s = {COMMIT, COMMIT};
    struct pair p;
    init(&p, 0, wrong_identity, &s);
    if (wrong_identity) CHECK(SSL_set1_host(p.client, "wrong.invalid"));
    drive(&p, 0);
    CHECK(p.failed && p.parsed && p.received == 0 && !p.cv_seen && !p.client_done);
    CHECK(SSL_get_verify_result(p.client) ==
          (wrong_identity ? X509_V_ERR_HOSTNAME_MISMATCH : X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    CHECK(s.preserve == COMMIT && s.restore == COMMIT);
    printf("ACTIVE-FAILURE %s cache=%u/%u verification=%ld\n",
           wrong_identity ? "hostname" : "chain", s.preserve, s.restore,
           SSL_get_verify_result(p.client));
    free_pair(&p);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: %s pq.crt pq.key pq-ca.crt ec.crt ec.key ec-ca.crt\n", argv[0]);
        return 2;
    }
    cert_path = argv[1]; key_path = argv[2]; ca_path = argv[3];
    classical_cert = argv[4]; classical_key = argv[5]; classical_ca = argv[6];
    printf("OpenSSL runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
    follow_loss();
    follow_withdrawal();
    active_failure(0);
    active_failure(1);
    puts("PASS: eight policy-consumption probes and two active-cache failure controls");
    return 0;
}
