/* Deterministic local cancellation of two live TLS handshakes.
 * No record modification, traffic-secret access or remote peer is involved.
 * The restore-on-cancel adapter is deliberately faulty application policy.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#define EXT 0xFDFD
#define COMMIT 86400U
#define CHECK(x) do { if (!(x)) die(#x); } while (0)
static const char *cert_path, *key_path, *ca_path;
static _Noreturn void die(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message); ERR_print_errors_fp(stderr); exit(2);
}
struct store { uint32_t preserve, restore; };
struct pair {
    SSL_CTX *cc, *sc;
    SSL *client, *server;
    unsigned char wire[4];
    uint32_t received, snapshot;
    int parsed, cv_seen, finished_seen, peer_pq, client_done, server_done, failed;
    int last_client_error;
    int send_extension;
};
static int add_server(SSL *s, unsigned int t, unsigned int context,
                      const unsigned char **out, size_t *len, X509 *x,
                      size_t index, int *alert, void *arg) {
    struct pair *p=arg;
    (void)s;(void)t;(void)x;(void)alert;
    if (!p->send_extension || !(context & SSL_EXT_TLS1_3_CERTIFICATE) || index!=0) return 0;
    *out=p->wire;*len=4;return 1;
}
static int add_client(SSL *s, unsigned int t, unsigned int context,
                      const unsigned char **out, size_t *len, X509 *x,
                      size_t index, int *alert, void *arg) {
    (void)s;(void)t;(void)x;(void)index;(void)alert;(void)arg;
    if (!(context & SSL_EXT_CLIENT_HELLO)) return 0;
    *out=NULL;*len=0;return 1;
}
static int parse(SSL *s,unsigned int t,unsigned int context,
                 const unsigned char *data,size_t len,X509 *x,
                 size_t index,int *alert,void *arg) {
    struct pair *p=arg;EVP_PKEY *key;
    (void)s;(void)t;(void)alert;
    if (!(context & SSL_EXT_TLS1_3_CERTIFICATE) || index!=0) return 1;
    if (len!=4) return 0;
    p->received=((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3];
    p->parsed=1;key=x?X509_get0_pubkey(x):NULL;
    p->peer_pq=key && EVP_PKEY_is_a(key,"ML-DSA-65");
    return 1; /* Tentative data only. No write to shared policy here. */
}
static void message(int write_p,int version,int type,const void *buf,size_t len,
                    SSL *s,void *arg) {
    struct pair *p=arg;const unsigned char *b=buf;
    (void)version;(void)s;
    if (write_p || type!=SSL3_RT_HANDSHAKE || len==0) return;
    if (b[0]==SSL3_MT_CERTIFICATE_VERIFY) p->cv_seen=1;
    if (b[0]==SSL3_MT_FINISHED) p->finished_seen=1;
}
static void init(struct pair *p,uint32_t value,int trusted,struct store *store) {
    memset(p,0,sizeof(*p));p->snapshot=store->restore;p->send_extension=1;
    for(int i=0;i<4;i++) p->wire[i]=(unsigned char)(value>>(24-8*i));
    p->cc=SSL_CTX_new(TLS_client_method());p->sc=SSL_CTX_new(TLS_server_method());
    CHECK(p->cc && p->sc);
    CHECK(SSL_CTX_set_min_proto_version(p->cc,TLS1_3_VERSION));
    CHECK(SSL_CTX_set_max_proto_version(p->cc,TLS1_3_VERSION));
    CHECK(SSL_CTX_set_min_proto_version(p->sc,TLS1_3_VERSION));
    CHECK(SSL_CTX_set_max_proto_version(p->sc,TLS1_3_VERSION));
    CHECK(SSL_CTX_set_ciphersuites(p->cc,"TLS_AES_128_GCM_SHA256"));
    CHECK(SSL_CTX_set_ciphersuites(p->sc,"TLS_AES_128_GCM_SHA256"));
    CHECK(SSL_CTX_use_certificate_chain_file(p->sc,cert_path)==1);
    CHECK(SSL_CTX_use_PrivateKey_file(p->sc,key_path,SSL_FILETYPE_PEM)==1);
    CHECK(SSL_CTX_check_private_key(p->sc)==1);
    SSL_CTX_set_verify(p->cc,SSL_VERIFY_PEER,NULL);
    if (trusted) CHECK(SSL_CTX_load_verify_locations(p->cc,ca_path,NULL)==1);
    CHECK(SSL_CTX_add_custom_ext(p->sc,EXT,SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_CERTIFICATE,
        add_server,NULL,p,NULL,NULL)==1);
    CHECK(SSL_CTX_add_custom_ext(p->cc,EXT,SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_CERTIFICATE,
        add_client,NULL,NULL,parse,p)==1);
    SSL_CTX_set_msg_callback(p->cc,message);SSL_CTX_set_msg_callback_arg(p->cc,p);
    p->client=SSL_new(p->cc);p->server=SSL_new(p->sc);CHECK(p->client && p->server);
    BIO *cr=BIO_new(BIO_s_mem()),*cw=BIO_new(BIO_s_mem());
    BIO *sr=BIO_new(BIO_s_mem()),*sw=BIO_new(BIO_s_mem());CHECK(cr && cw && sr && sw);
    BIO_set_mem_eof_return(cr,-1);BIO_set_mem_eof_return(sr,-1);
    SSL_set_bio(p->client,cr,cw);SSL_set_bio(p->server,sr,sw);
    SSL_set_hostflags(p->client,X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    CHECK(SSL_set1_host(p->client,"localhost"));
    CHECK(SSL_set_tlsext_host_name(p->client,"localhost"));
    SSL_set_connect_state(p->client);SSL_set_accept_state(p->server);
}
/* Transport one complete, unchanged TLS record between local memory BIOs. */
static int pump(SSL *from,SSL *to) {
    char *data=NULL;BIO *out=SSL_get_wbio(from);long have=BIO_get_mem_data(out,&data);
    if(have<5) return 0;
    size_t size=5U+((size_t)(unsigned char)data[3]<<8)+(unsigned char)data[4];
    if((size_t)have<size) return 0;
    unsigned char *copy=malloc(size);CHECK(copy);
    CHECK(BIO_read(out,copy,(int)size)==(int)size);
    CHECK(BIO_write(SSL_get_rbio(to),copy,(int)size)==(int)size);free(copy);return 1;
}
static int paused(struct pair *p) {
    return p->parsed && p->peer_pq && p->cv_seen && !p->finished_seen && !p->failed
        && !p->client_done && !SSL_is_init_finished(p->client)
        && SSL_get_state(p->client)==TLS_ST_CR_CERT_VRFY
        && p->last_client_error==SSL_ERROR_WANT_READ
        && BIO_ctrl_pending(SSL_get_rbio(p->client))==0
        && SSL_get_verify_result(p->client)==X509_V_OK;
}
static int step(SSL *s,int *done,int *failed) {
    ERR_clear_error();int ret=SSL_do_handshake(s);
    if(ret==1) {*done=1;return SSL_ERROR_NONE;}
    int err=SSL_get_error(s,ret);
    if(err!=SSL_ERROR_WANT_READ && err!=SSL_ERROR_WANT_WRITE) *failed=1;
    return err;
}
static void drive(struct pair *p,int stop_before_finished) {
    for(int i=0;i<1000;i++) {
        if(!p->client_done && !p->failed) p->last_client_error=step(p->client,&p->client_done,&p->failed);
        if(stop_before_finished && paused(p)) return;
        if(p->failed) return;
        while(pump(p->client,p->server)) {}
        if(!p->server_done) step(p->server,&p->server_done,&p->failed);
        if(p->failed || (p->client_done && p->server_done)) return;
        (void)pump(p->server,p->client);
    }
    die("handshake stalled");
}
static void commit(struct pair *p,struct store *s) {
    CHECK(p->client_done && p->server_done && !p->failed);
    CHECK(SSL_is_init_finished(p->client) && SSL_get_verify_result(p->client)==X509_V_OK);
    X509 *cert=SSL_get0_peer_certificate(p->client);
    EVP_PKEY *key=cert?X509_get0_pubkey(cert):NULL;
    CHECK(key && EVP_PKEY_is_a(key,"ML-DSA-65"));
    /* Successful omission preserves state; zero and omission are distinct. */
    if(p->parsed) s->preserve=s->restore=p->received;
}
static void free_pair(struct pair *p) {
    SSL_free(p->client);SSL_free(p->server);SSL_CTX_free(p->cc);SSL_CTX_free(p->sc);
    p->client=p->server=NULL;ERR_clear_error();
}
static void run_case(const char *name,int b_trusted,int a_completes) {
    struct store s={0,0};struct pair a,b;
    printf("\nCASE %s\n",name);
    init(&a,0,1,&s);drive(&a,1);CHECK(paused(&a));
    printf("  A paused: verified_chain=yes ML-DSA-65=yes state=TLS_ST_CR_CERT_VRFY waiting_read=yes finished_seen=0 snapshot=%u\n",a.snapshot);
    init(&b,COMMIT,b_trusted,&s);drive(&b,0);
    if(b_trusted) {
        commit(&b,&s);CHECK(s.preserve==COMMIT && s.restore==COMMIT);
        printf("  B completed: received=%u preserve=%u restore=%u\n",b.received,s.preserve,s.restore);
    } else {
        CHECK(b.failed && !b.client_done && !b.cv_seen && b.parsed && b.peer_pq);
        CHECK(SSL_get_verify_result(b.client)!=X509_V_OK);
        CHECK(s.preserve==0 && s.restore==0);
        printf("  B failed chain validation: candidate=%u committed=no verify=%ld\n",b.received,SSL_get_verify_result(b.client));
    }
    CHECK(paused(&a)); /* B's execution did not process A's Finished. */
    if(a_completes) {
        drive(&a,0);commit(&a,&s);CHECK(a.received==0);
        printf("  A completed: adapter applies received zero; preserve=%u restore=%u\n",s.preserve,s.restore);
        CHECK(s.preserve==0 && s.restore==0);
    } else {
        /* Ordinary application cancellation: destroy A without processing Finished. */
        uint32_t snapshot=a.snapshot;free_pair(&a);
        s.restore=snapshot; /* Intentional bad adapter; preserve makes no write. */
        CHECK(s.preserve==(b_trusted?COMMIT:0) && s.restore==0);
        printf("  A locally cancelled: preserve=%u restore=%u\n",s.preserve,s.restore);
    }
    free_pair(&b);if(a.client) free_pair(&a);
    printf("  CASE PASS\n");
}
static void run_seeded_case(const char *name,int omit) {
    struct store s={0,0};struct pair seed,a,b;
    printf("\nCASE %s\n",name);
    init(&seed,COMMIT,1,&s);drive(&seed,0);commit(&seed,&s);free_pair(&seed);
    CHECK(s.preserve==COMMIT && s.restore==COMMIT);
    printf("  Seed completed: preserve=%u restore=%u\n",s.preserve,s.restore);
    init(&a,0,1,&s);drive(&a,1);CHECK(paused(&a));CHECK(a.snapshot==COMMIT);
    init(&b,0,1,&s);b.send_extension=!omit;drive(&b,0);commit(&b,&s);
    CHECK(b.parsed==!omit);
    uint32_t expected=omit?COMMIT:0;
    CHECK(s.preserve==expected && s.restore==expected);CHECK(paused(&a));
    printf("  B completed: extension=%s preserve=%u restore=%u\n",
        omit?"omitted":"zero",s.preserve,s.restore);
    uint32_t snapshot=a.snapshot;free_pair(&a);s.restore=snapshot;
    CHECK(s.preserve==expected && s.restore==COMMIT);
    printf("  A locally cancelled: preserve=%u restore=%u\n",s.preserve,s.restore);
    free_pair(&b);puts("  CASE PASS");
}
static void run_wrong_identity(void) {
    struct store s={0,0};struct pair a;
    puts("\nCASE wrong reference identity rejected");
    init(&a,COMMIT,1,&s);
    CHECK(SSL_set1_host(a.client,"wrong.invalid"));
    drive(&a,0);
    CHECK(a.failed && !a.client_done && !a.cv_seen && a.parsed);
    CHECK(SSL_get_verify_result(a.client)==X509_V_ERR_HOSTNAME_MISMATCH);
    CHECK(s.preserve==0 && s.restore==0);
    printf("  Verification=%ld; no CV completion or policy update\n",SSL_get_verify_result(a.client));
    free_pair(&a);puts("  CASE PASS");
}
int main(int argc,char **argv) {
    if(argc!=4) {fprintf(stderr,"usage: %s server.crt server.key ca.crt\n",argv[0]);return 2;}
    cert_path=argv[1];key_path=argv[2];ca_path=argv[3];
    printf("OpenSSL runtime: %s\n",OpenSSL_version(OPENSSL_VERSION));
    run_case("B commits, A cancelled",1,0);
    run_case("B untrusted, A cancelled",0,0);
    run_case("B commits, A completes zero update",1,1);
    run_seeded_case("B withdraws seeded commitment, A cancelled",0);
    run_seeded_case("B omits extension on seeded state, A cancelled",1);
    run_wrong_identity();
    puts("PASS: deterministic overlap; rollback is in the deliberately faulty adapter");
    return 0;
}
