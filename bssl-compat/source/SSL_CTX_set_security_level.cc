#include <openssl/ssl.h>
#include <ossl.h>

extern "C" void SSL_CTX_set_security_level(SSL_CTX* ctx, int level) {
  ossl.ossl_SSL_CTX_set_security_level(ctx, level);
}
