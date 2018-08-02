#include "common/ssl/context_impl.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/runtime/runtime.h"

#include "common/common/assert.h"
#include "common/common/base64.h"
#include "common/common/fmt.h"
#include "common/common/hex.h"
#include "common/ssl/utility.h"

#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"

namespace Envoy {
namespace Ssl {

int ContextImpl::sslContextIndex() {
  CONSTRUCT_ON_FIRST_USE(int, []() -> int {
    int ssl_context_index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    RELEASE_ASSERT(ssl_context_index >= 0, "");
    return ssl_context_index;
  }());
}

ContextImpl::ContextImpl(Stats::Scope& scope, const ContextConfig& config)
    : ctx_(SSL_CTX_new(TLS_method())), scope_(scope), stats_(generateStats(scope)) {
  RELEASE_ASSERT(ctx_, "");

  int rc = SSL_CTX_set_ex_data(ctx_, sslContextIndex(), this);
  RELEASE_ASSERT(rc == 1, "");

  //rc = SSL_CTX_set_min_proto_version(ctx_, config.minProtocolVersion());
  //RELEASE_ASSERT(rc == 1, "");

  //rc = SSL_CTX_set_max_proto_version(ctx_, config.maxProtocolVersion());
  //RELEASE_ASSERT(rc == 1, "");

  size_t num_ciphers = std::count(config.cipherSuites().begin(), config.cipherSuites().end(), ':') + 1;

  SSL_CTX_set_cipher_list(ctx_, config.cipherSuites().c_str());
  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx_);

  int num_valid_ciphers = sk_SSL_CIPHER_num(ciphers);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 1 \n";
  char *dup = strdup(config.cipherSuites().c_str());
  char *token = std::strtok(dup, ":[]|");
  while (token != NULL) {
    bool found=false;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
      std::string str1(token);
      if (str1.compare(SSL_CIPHER_get_name(cipher)) == 0){
        found = true;
      }
    }
    if (!found){
      delete dup;
      free();
      throw EnvoyException(
        fmt::format("Failed to initialize cipher suites {}", config.cipherSuites()));
    }
    token = std::strtok(NULL, ":[]|");
  }
  delete dup;

  if (!SSL_CTX_set1_curves_list(ctx_, config.ecdhCurves().c_str())) {
    throw EnvoyException(fmt::format("Failed to initialize ECDH curves {}", config.ecdhCurves()));
  }

  int verify_mode = SSL_VERIFY_NONE;
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2 \n";
  if (!config.caCert().empty()) {
    ca_file_path_ = config.caCertPath();

    BIO *ca_cert_bio = BIO_new_mem_buf(const_cast<char*>(config.caCert().data()), config.caCert().size());

std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.1.1 \n";
    RELEASE_ASSERT(ca_cert_bio != nullptr, "");
    // Based on BoringSSL's X509_load_cert_crl_file().
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.1.2 " << ca_cert_bio << "\n";

    STACK_OF(X509_INFO) *ca_cert_list = PEM_X509_INFO_read_bio(ca_cert_bio, nullptr, nullptr, nullptr);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.1.3 \n";

    if (ca_cert_list == nullptr) {
      free();
      throw EnvoyException(
          fmt::format("Failed to load trusted CA certificates from {}", config.caCertPath()));
    }

        X509_STORE* store = SSL_CTX_get_cert_store(ctx_);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.2 " << sk_X509_INFO_num(ca_cert_list) << "\n";
    for (int i = 0; i < sk_X509_INFO_num(ca_cert_list); i++) {
      X509_INFO *item = sk_X509_INFO_value(ca_cert_list, i);
std::cerr << "!!!!!!!!!!!!!!!!!! item " << i << "\n";
      if (item->x509) {
        X509_STORE_add_cert(store, item->x509);
        if (ca_cert_ == nullptr) {
std::cerr << "!!!!!!!!!!!!!!!!!!!! ca_cert_ == nullptr \n";
          ca_cert_ = item->x509;
        }
      }
item->x509 = NULL;
      if (item->crl) {
        X509_STORE_add_crl(store, item->crl);
      }
    }
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.4 \n";

    if (ca_cert_ == nullptr) {
      free();
      throw EnvoyException(
          fmt::format("Failed to load trusted CA certificates from {}", config.caCertPath()));
    }
    verify_mode = SSL_VERIFY_PEER;
    verify_trusted_ca_ = true;

    BIO_free(ca_cert_bio);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.5 \n";

    // Bill - this does not free the underlying x509 object
    sk_X509_INFO_pop_free(ca_cert_list, X509_INFO_free);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 2.8 \n";

    // NOTE: We're using SSL_CTX_set_cert_verify_callback() instead of X509_verify_cert()
    // directly. However, our new callback is still calling X509_verify_cert() under
    // the hood. Therefore, to ignore cert expiration, we need to set the callback
    // for X509_verify_cert to ignore that error.
    if (config.allowExpiredCertificate()) {
      X509_STORE_set_verify_cb(store, ContextImpl::ignoreCertificateExpirationCallback);
    }
  }

  if (!config.certificateRevocationList().empty()) {
    BIO *crl_bio = BIO_new_mem_buf(const_cast<char*>(config.certificateRevocationList().data()),
                        config.certificateRevocationList().size());

    RELEASE_ASSERT(crl_bio != nullptr, "");
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.0.5 \n";

    // Based on BoringSSL's X509_load_cert_crl_file().
    STACK_OF(X509_INFO) *crl_list = PEM_X509_INFO_read_bio(crl_bio, nullptr, nullptr, nullptr);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.2 \n";

    if (crl_list == nullptr) {
      free();
      BIO_free(crl_bio);
      throw EnvoyException(
          fmt::format("Failed to load CRL from {}", config.certificateRevocationListPath()));
    }
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.3 \n";
    X509_STORE* store = SSL_CTX_get_cert_store(ctx_);
    std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.4 \n";
    for (int i = 0; i < sk_X509_INFO_num(crl_list); i++) {
      X509_INFO *item = sk_X509_INFO_value(crl_list, i);
      if (item->crl) {
        X509_STORE_add_crl(store, item->crl);
      }
    }

std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.6 \n";
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 3.9 \n";

    BIO_free(crl_bio);
    sk_X509_INFO_pop_free(crl_list, X509_INFO_free);

  }

  if (!config.verifySubjectAltNameList().empty()) {
    verify_subject_alt_name_list_ = config.verifySubjectAltNameList();
    verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }

  if (!config.verifyCertificateHashList().empty()) {
    for (auto hash : config.verifyCertificateHashList()) {
      // Remove colons from the 95 chars long colon-separated "fingerprint"
      // in order to get the hex-encoded string.
      if (hash.size() == 95) {
        hash.erase(std::remove(hash.begin(), hash.end(), ':'), hash.end());
      }
      const auto& decoded = Hex::decode(hash);
      if (decoded.size() != SHA256_DIGEST_LENGTH) {
        free();
        throw EnvoyException(fmt::format("Invalid hex-encoded SHA-256 {}", hash));
      }
      verify_certificate_hash_list_.push_back(decoded);
    }
    verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }

  if (!config.verifyCertificateSpkiList().empty()) {
    for (auto hash : config.verifyCertificateSpkiList()) {
      const auto decoded = Base64::decode(hash);
      if (decoded.size() != SHA256_DIGEST_LENGTH) {
        free();
        throw EnvoyException(fmt::format("Invalid base64-encoded SHA-256 {}", hash));
      }
      verify_certificate_spki_list_.emplace_back(decoded.begin(), decoded.end());
    }
    verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }

  if (verify_mode != SSL_VERIFY_NONE) {
    SSL_CTX_set_verify(ctx_, verify_mode, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx_, ContextImpl::verifyCallback, this);
  }

  if (config.certChain().empty() != config.privateKey().empty()) {
    free();
    throw EnvoyException(fmt::format("Failed to load incomplete certificate from {}, {}",
                                     config.certChainPath(), config.privateKeyPath()));
  }
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 5 \n";
  if (!config.certChain().empty()) {
    // Load certificate chain.
    cert_chain_file_path_ = config.certChainPath();
    BIO *chain_bio = BIO_new_mem_buf(const_cast<char*>(config.certChain().data()), config.certChain().size());
    RELEASE_ASSERT(chain_bio != nullptr, "");
    
    cert_chain_ = PEM_read_bio_X509_AUX(chain_bio, nullptr, nullptr, nullptr);
    if (cert_chain_ == nullptr || !SSL_CTX_use_certificate(ctx_, cert_chain_)) {
      free();
      throw EnvoyException(
          fmt::format("Failed to load certificate chain from {}", config.certChainPath()));
    }

std::cerr << "!!!!!!!!!!!!! use_certificate " << cert_chain_ << "\n";

    if (cert_chain_ == nullptr || !SSL_CTX_use_certificate(ctx_, cert_chain_)) {
      free();
      throw EnvoyException(
          fmt::format("Failed to load certificate chain from {}", config.certChainPath()));
    }
    // Read rest of the certificate chain.
    while (true) {
      X509* chain_cert(PEM_read_bio_X509(chain_bio, nullptr, nullptr, nullptr));
      std::cerr << "!!!!!!!!!!!!! chain_cert " << chain_cert << "\n";

      if (chain_cert == nullptr) {
        break;
      }
       if (!SSL_CTX_add_extra_chain_cert(ctx_, chain_cert)) {
        free();
        throw EnvoyException(
            fmt::format("Failed to load certificate chain from {}", config.certChainPath()));
      }
      // SSL_CTX_add_extra_chain_cert() takes ownership.
      X509_free(chain_cert);
    }
    // Check for EOF.
    uint32_t err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
    } else {
      free();
      throw EnvoyException(
          fmt::format("Failed to load certificate chain from {}", config.certChainPath()));
    }

    BIO_free(chain_bio);
std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl 6 \n";

    // Load private key.
    BIO *key_bio = BIO_new_mem_buf(const_cast<char*>(config.privateKey().data()), config.privateKey().size());
    RELEASE_ASSERT(key_bio != nullptr, "");
    EVP_PKEY* pkey(PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr));
    if (pkey == nullptr || !SSL_CTX_use_PrivateKey(ctx_, pkey)) {
      free();
      throw EnvoyException(
          fmt::format("Failed to load private key from {}", config.privateKeyPath()));
    }
    BIO_free(key_bio);
    EVP_PKEY_free(pkey);

  }

  // use the server's cipher list preferences
  SSL_CTX_set_options(ctx_, SSL_OP_CIPHER_SERVER_PREFERENCE);

  parsed_alpn_protocols_ = parseAlpnProtocols(config.alpnProtocols());

  std::cerr << "!!!!!!!!!!!!!!!!!!!! ContextImpl done \n";
}

int ServerContextImpl::alpnSelectCallback(const unsigned char** out, unsigned char* outlen,
                                          const unsigned char* in, unsigned int inlen) {
  // Currently this uses the standard selection algorithm in priority order.
  const uint8_t* alpn_data = &parsed_alpn_protocols_[0];
  size_t alpn_data_size = parsed_alpn_protocols_.size();
  if (!parsed_alt_alpn_protocols_.empty() &&
      runtime_.snapshot().featureEnabled("ssl.alt_alpn", 0)) {
    alpn_data = &parsed_alt_alpn_protocols_[0];
    alpn_data_size = parsed_alt_alpn_protocols_.size();
  }

  if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, alpn_data, alpn_data_size, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  } else {
    return SSL_TLSEXT_ERR_OK;
  }
}

std::vector<uint8_t> ContextImpl::parseAlpnProtocols(const std::string& alpn_protocols) {
  if (alpn_protocols.empty()) {
    return {};
  }

  if (alpn_protocols.size() >= 65535) {
    throw EnvoyException("invalid ALPN protocol string");
  }

  std::vector<uint8_t> out(alpn_protocols.size() + 1);
  size_t start = 0;
  for (size_t i = 0; i <= alpn_protocols.size(); i++) {
    if (i == alpn_protocols.size() || alpn_protocols[i] == ',') {
      if (i - start > 255) {
        throw EnvoyException("invalid ALPN protocol string");
      }

      out[start] = i - start;
      start = i + 1;
    } else {
      out[i + 1] = alpn_protocols[i];
    }
  }

  return out;
}

SSL* ContextImpl::newSsl() const {
  return SSL_new(ctx_);
}

int ContextImpl::ignoreCertificateExpirationCallback(int ok, X509_STORE_CTX* ctx) {
  if (!ok) {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_CERT_HAS_EXPIRED || err == X509_V_ERR_CERT_NOT_YET_VALID) {
      return 1;
    }
  }

  return ok;
}

int ContextImpl::verifyCallback(X509_STORE_CTX* store_ctx, void* arg) {
  ContextImpl* impl = reinterpret_cast<ContextImpl*>(arg);

  if (impl->verify_trusted_ca_) {
    int ret = X509_verify_cert(store_ctx);
    if (ret <= 0) {
      impl->stats_.fail_verify_error_.inc();
      return ret;
    }
  }

  SSL* ssl = reinterpret_cast<SSL*>(
      X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
  X509* cert(SSL_get_peer_certificate(ssl));
  int verified = impl->verifyCertificate(cert);
  X509_free(cert);
  return verified;

}

int ContextImpl::verifyCertificate(X509* cert) {
  if (!verify_subject_alt_name_list_.empty() &&
      !verifySubjectAltName(cert, verify_subject_alt_name_list_)) {
    stats_.fail_verify_san_.inc();
    return 0;
  }

  if (!verify_certificate_hash_list_.empty() || !verify_certificate_spki_list_.empty()) {
    const bool valid_certificate_hash =
        !verify_certificate_hash_list_.empty() &&
        verifyCertificateHashList(cert, verify_certificate_hash_list_);
    const bool valid_certificate_spki =
        !verify_certificate_spki_list_.empty() &&
        verifyCertificateSpkiList(cert, verify_certificate_spki_list_);

    if (!valid_certificate_hash && !valid_certificate_spki) {
      stats_.fail_verify_cert_hash_.inc();
      return 0;
    }
  }

  return 1;
}

void ContextImpl::logHandshake(SSL* ssl) const {
  stats_.handshake_.inc();

  if (SSL_session_reused(ssl)) {
    stats_.session_reused_.inc();
  }

  const char* cipher = SSL_get_cipher_name(ssl);
  scope_.counter(fmt::format("ssl.ciphers.{}", std::string{cipher})).inc();

  X509* cert(SSL_get_peer_certificate(ssl));
  if (!cert) {
    stats_.no_certificate_.inc();
  }
  X509_free(cert);

}

bool ContextImpl::verifySubjectAltName(X509* cert,
                                       const std::vector<std::string>& subject_alt_names) {
  bool verified = false;

  STACK_OF(GENERAL_NAME)* altnames = static_cast<STACK_OF(GENERAL_NAME)*>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

  if (altnames) {
    int n = sk_GENERAL_NAME_num(altnames);
    for (int i = 0; i < n && !verified; i++) {
      GENERAL_NAME* altname = sk_GENERAL_NAME_value(altnames, i);

      if (altname->type == GEN_DNS) {
        ASN1_STRING* str = altname->d.dNSName;
        char* dns_name = reinterpret_cast<char*>(ASN1_STRING_data(str));
        for (auto& config_san : subject_alt_names) {
          if (dNSNameMatch(config_san, dns_name)) {
            verified = true;
            break;
          }
        }
      } else if (altname->type == GEN_URI) {
        ASN1_STRING* str = altname->d.uniformResourceIdentifier;
        char* crt_san = reinterpret_cast<char*>(ASN1_STRING_data(str));
        for (auto& config_san : subject_alt_names) {
          if (config_san.compare(crt_san) == 0) {
            verified = true;
            break;
          }
        }
      }
    }

    sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
  }

  return verified;

}

bool ContextImpl::dNSNameMatch(const std::string& dNSName, const char* pattern) {
  if (dNSName == pattern) {
    return true;
  }

  size_t pattern_len = strlen(pattern);
  if (pattern_len > 1 && pattern[0] == '*' && pattern[1] == '.') {
    if (dNSName.length() > pattern_len - 1) {
      size_t off = dNSName.length() - pattern_len + 1;
      return dNSName.compare(off, pattern_len - 1, pattern + 1) == 0;
    }
  }

  return false;
}

bool ContextImpl::verifyCertificateHashList(
    X509* cert, const std::vector<std::vector<uint8_t>>& expected_hashes) {
  std::vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert, EVP_sha256(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");

  for (const auto& expected_hash : expected_hashes) {
    if (computed_hash == expected_hash) {
      return true;
    }
  }
  return false;
}

bool ContextImpl::verifyCertificateSpkiList(
    X509* cert, const std::vector<std::vector<uint8_t>>& expected_hashes) {
  X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
  if (pubkey == nullptr) {
    return false;
  }
  uint8_t* spki = nullptr;
  const int len = i2d_X509_PUBKEY(pubkey, &spki);
  if (len < 0) {
    return false;
  }
  uint8_t* free_spki(spki);

  std::vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
  SHA256(spki, len, computed_hash.data());

  for (const auto& expected_hash : expected_hashes) {
    if (computed_hash == expected_hash) {
      return true;
    }
  }
  return false;
}

SslStats ContextImpl::generateStats(Stats::Scope& store) {
  std::string prefix("ssl.");
  return {ALL_SSL_STATS(POOL_COUNTER_PREFIX(store, prefix), POOL_GAUGE_PREFIX(store, prefix),
                        POOL_HISTOGRAM_PREFIX(store, prefix))};
}

size_t ContextImpl::daysUntilFirstCertExpires() const {
  int daysUntilExpiration = getDaysUntilExpiration(ca_cert_);
  daysUntilExpiration =
      std::min<int>(getDaysUntilExpiration(cert_chain_), daysUntilExpiration);
  if (daysUntilExpiration < 0) { // Ensure that the return value is unsigned
    return 0;
  }
  return daysUntilExpiration;
}

int32_t ContextImpl::getDaysUntilExpiration(const X509* cert) const {
  if (cert == nullptr) {
    return std::numeric_limits<int>::max();
  }
  int days, seconds;
  if (ASN1_TIME_diff(&days, &seconds, nullptr, X509_get_notAfter(cert))) {
    return days;
  }
  return 0;
}

std::string ContextImpl::getCaCertInformation() const {
  if (ca_cert_ == nullptr) {
    return "";
  }
  return fmt::format("Certificate Path: {}, Serial Number: {}, Days until Expiration: {}",
                     getCaFileName(), Utility::getSerialNumberFromCertificate(ca_cert_),
                     getDaysUntilExpiration(ca_cert_));
}

std::string ContextImpl::getCertChainInformation() const {
  if (cert_chain_ == nullptr) {
    return "";
  }
  return fmt::format("Certificate Path: {}, Serial Number: {}, Days until Expiration: {}",
                     getCertChainFileName(),
                     Utility::getSerialNumberFromCertificate(cert_chain_),
                     getDaysUntilExpiration(cert_chain_));
}

ClientContextImpl::ClientContextImpl(Stats::Scope& scope, const ClientContextConfig& config)
    : ContextImpl(scope, config), server_name_indication_(config.serverNameIndication()),
      allow_renegotiation_(config.allowRenegotiation()) {

std::cerr << "!!!!!!!!!!!!!!!!!!!! ClientContextImpl \n";
  if (!parsed_alpn_protocols_.empty()) {
    int rc = SSL_CTX_set_alpn_protos(ctx_, &parsed_alpn_protocols_[0],
                                     parsed_alpn_protocols_.size());
    RELEASE_ASSERT(rc == 0, "");
  }
}

SSL* ClientContextImpl::newSsl() const {
  SSL* ssl_con(ContextImpl::newSsl());

  if (!server_name_indication_.empty()) {
    int rc = SSL_set_tlsext_host_name(ssl_con, server_name_indication_.c_str());
    RELEASE_ASSERT(rc, "");
    UNREFERENCED_PARAMETER(rc);
  }

  return ssl_con;
}

ServerContextImpl::ServerContextImpl(Stats::Scope& scope, const ServerContextConfig& config,
                                     const std::vector<std::string>& server_names,
                                     Runtime::Loader& runtime)
    : ContextImpl(scope, config), runtime_(runtime),
      session_ticket_keys_(config.sessionTicketKeys()) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ServerContextImpl \n";

  SSL_CTX_set_cert_cb(ctx_, cert_cb, nullptr);

  if (config.certChain().empty()) {
    throw EnvoyException("Server TlsCertificates must have a certificate specified");
  }
  if (!config.caCert().empty()) {
    BIO* bio(
        BIO_new_mem_buf(const_cast<char*>(config.caCert().data()), config.caCert().size()));

    RELEASE_ASSERT(bio != nullptr, "");
    // Based on BoringSSL's SSL_add_file_cert_subjects_to_stack().
    STACK_OF(X509_NAME)* list(sk_X509_NAME_new(xname_cmp));
    RELEASE_ASSERT(list != nullptr, "");
    for (;;) {
      X509* cert(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr));
      if (cert == nullptr) {
        break;
      }
      X509_NAME* name = X509_get_subject_name(cert);
      if (name == nullptr) {
        BIO_free(bio);
        X509_free(cert);
        sk_X509_NAME_pop_free(list, X509_NAME_free);
        free();
        throw EnvoyException(fmt::format("Failed to load trusted client CA certificates from {}",
                                         config.caCertPath()));
      }
      // Check for duplicates.
      if (sk_X509_NAME_find(list, name)) {
        X509_free(cert);
        continue;
      }
      X509_NAME* name_dup(X509_NAME_dup(name));
      if (name_dup == nullptr || !sk_X509_NAME_push(list, name_dup)) {
        BIO_free(bio);
        X509_free(cert);
        sk_X509_NAME_pop_free(list, X509_NAME_free);
        free();
        throw EnvoyException(fmt::format("Failed to load trusted client CA certificates from {}",
                                         config.caCertPath()));
      }
      X509_free(cert);
      X509_NAME_free(name_dup);
    }

std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! 1 \n";
    // Check for EOF.
    uint32_t err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
    } else {
      BIO_free(bio);
      sk_X509_NAME_pop_free(list, X509_NAME_free);
      throw EnvoyException(fmt::format("Failed to load trusted client CA certificates from {}",
                                       config.caCertPath()));
    }
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! 1.5 \n";
    SSL_CTX_set_client_CA_list(ctx_, list);

    // SSL_VERIFY_PEER or stronger mode was already set in ContextImpl::ContextImpl().
    if (config.requireClientCertificate()) {
      SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! 2 \n";
//    sk_X509_NAME_pop_free(list, X509_NAME_free);
    BIO_free(bio);

  }

  parsed_alt_alpn_protocols_ = parseAlpnProtocols(config.altAlpnProtocols());

  if (!parsed_alpn_protocols_.empty()) {
    SSL_CTX_set_alpn_select_cb(ctx_,
                               [](SSL*, const unsigned char** out, unsigned char* outlen,
                                  const unsigned char* in, unsigned int inlen, void* arg) -> int {
                                 return static_cast<ServerContextImpl*>(arg)->alpnSelectCallback(
                                     out, outlen, in, inlen);
                               },
                               this);
  }

  if (!session_ticket_keys_.empty()) {
    SSL_CTX_set_tlsext_ticket_key_cb(ctx_, ssl_tlsext_ticket_key_cb);
  }

//    SSL_CTX_set_tlsext_ticket_key_cb(
//        ctx_,
//        [](SSL* ssl, uint8_t* key_name, uint8_t* iv, EVP_CIPHER_CTX* ctx, HMAC_CTX* hmac_ctx,
//           int encrypt) -> int {
//          ContextImpl* context_impl = static_cast<ContextImpl*>(
//              SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), sslContextIndex()));
//          ServerContextImpl* server_context_impl = dynamic_cast<ServerContextImpl*>(context_impl);
//          RELEASE_ASSERT(server_context_impl != nullptr, ""); // for Coverity
//          return server_context_impl->sessionTicketProcess(ssl, key_name, iv, ctx, hmac_ctx,
//                                                           encrypt);
//       });
//  }
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! 3 \n";
  uint8_t session_context_buf[EVP_MAX_MD_SIZE] = {};
  unsigned session_context_len = 0;
  EVP_MD_CTX* md(EVP_MD_CTX_new());
  int rc = EVP_DigestInit(md, EVP_sha256());
  RELEASE_ASSERT(rc == 1, "");
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! 4 \n";
  // Hash the CommonName/SANs of the server certificate. This makes sure that
  // sessions can only be resumed to a certificate for the same name, but allows
  // resuming to unique certs in the case that different Envoy instances each have
  // their own certs.
  X509* cert = SSL_CTX_get0_certificate(ctx_);
  RELEASE_ASSERT(cert != nullptr, "");
  X509_NAME* cert_subject = X509_get_subject_name(cert);
  RELEASE_ASSERT(cert_subject != nullptr, "");
  int cn_index = X509_NAME_get_index_by_NID(cert_subject, NID_commonName, -1);
  // It's possible that the certificate doesn't have CommonName, but has SANs.
  if (cn_index >= 0) {
    X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(cert_subject, cn_index);
    RELEASE_ASSERT(cn_entry != nullptr, "");
    ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    RELEASE_ASSERT(ASN1_STRING_length(cn_asn1) > 0, "");
    rc = EVP_DigestUpdate(md, ASN1_STRING_data(cn_asn1), ASN1_STRING_length(cn_asn1));
    RELEASE_ASSERT(rc == 1, "");
  }

  GENERAL_NAMES* san_names(
      static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)));
  if (san_names != nullptr) {
    std::cerr << "!!!!!!!!!!!!!!!! sk_GENERAL_NAME_num(san_names) " << sk_GENERAL_NAME_num(san_names) << "\n";
    for (size_t i = 0; i < sk_GENERAL_NAME_num(san_names); i++) {
      const GENERAL_NAME* san = sk_GENERAL_NAME_value(san_names, i);
      if (san->type == GEN_DNS || san->type == GEN_URI) {
        rc = EVP_DigestUpdate(md, ASN1_STRING_data(san->d.ia5), ASN1_STRING_length(san->d.ia5));
        RELEASE_ASSERT(rc == 1, "");
      }
    }
    GENERAL_NAMES_free(san_names);
  } else {
    // Make sure that we have either CommonName or SANs.
    RELEASE_ASSERT(cn_index >= 0, "");
  }

  X509_NAME* cert_issuer_name = X509_get_issuer_name(cert);
  rc = X509_NAME_digest(cert_issuer_name, EVP_sha256(), session_context_buf, &session_context_len);
  RELEASE_ASSERT(rc == 1 && session_context_len == SHA256_DIGEST_LENGTH, "");
  rc = EVP_DigestUpdate(md, session_context_buf, session_context_len);
  RELEASE_ASSERT(rc == 1, "");

  // Hash all the settings that affect whether the server will allow/accept
  // the client connection. This ensures that the client is always validated against
  // the correct settings, even if session resumption across different listeners
  // is enabled.
  if (ca_cert_ != nullptr) {
    rc = X509_digest(ca_cert_, EVP_sha256(), session_context_buf, &session_context_len);
    RELEASE_ASSERT(rc == 1 && session_context_len == SHA256_DIGEST_LENGTH, "");
    rc = EVP_DigestUpdate(md, session_context_buf, session_context_len);
    RELEASE_ASSERT(rc == 1, "");

    // verify_subject_alt_name_list_ can only be set with a ca_cert
    for (const std::string& name : verify_subject_alt_name_list_) {
      rc = EVP_DigestUpdate(md, name.data(), name.size());
      RELEASE_ASSERT(rc == 1, "");
    }
  }

  for (const auto& hash : verify_certificate_hash_list_) {
    rc = EVP_DigestUpdate(md, hash.data(),
                          hash.size() *
                              sizeof(std::remove_reference<decltype(hash)>::type::value_type));
    RELEASE_ASSERT(rc == 1, "");
  }

  for (const auto& hash : verify_certificate_spki_list_) {
    rc = EVP_DigestUpdate(md, hash.data(),
                          hash.size() *
                              sizeof(std::remove_reference<decltype(hash)>::type::value_type));
    RELEASE_ASSERT(rc == 1, "");
  }

  // Hash configured SNIs for this context, so that sessions cannot be resumed across different
  // filter chains, even when using the same server certificate.
  for (const auto& name : server_names) {
    rc = EVP_DigestUpdate(md, name.data(), name.size());
    RELEASE_ASSERT(rc == 1, "");
  }

  rc = EVP_DigestFinal(md, session_context_buf, &session_context_len);
  RELEASE_ASSERT(rc == 1, "");
  rc = SSL_CTX_set_session_id_context(ctx_, session_context_buf, session_context_len);
  RELEASE_ASSERT(rc == 1, "");

  EVP_MD_CTX_free(md);

std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! ServerContextImpl done \n";
}

int ServerContextImpl::cert_cb(SSL *ssl, void *arg)
{
std::cerr << "!!!!!!!!!!!!!!!!!! cert_cb \n";
  return 1;
}

int ServerContextImpl::xname_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
{
    return(X509_NAME_cmp(*a,*b));
}

int ServerContextImpl::ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
std::cerr << "!!!!!!!!!!!!!!!!!! ssl_tlsext_ticket_key_cb \n";
  return 1;
}

int ServerContextImpl::sessionTicketProcess(SSL*, uint8_t* key_name, uint8_t* iv,
                                            EVP_CIPHER_CTX* ctx, HMAC_CTX* hmac_ctx, int encrypt) {
  const EVP_MD* hmac = EVP_sha256();
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();

  if (encrypt == 1) {
    // Encrypt
    RELEASE_ASSERT(session_ticket_keys_.size() >= 1, "");
    // TODO(ggreenway): validate in SDS that session_ticket_keys_ cannot be empty,
    // or if we allow it to be emptied, reconfigure the context so this callback
    // isn't set.

    const ServerContextConfig::SessionTicketKey& key = session_ticket_keys_.front();

    // SSL_TICKET_KEY_NAME_LEN =16 for openssl
    static_assert(std::tuple_size<decltype(key.name_)>::value == 16,
        "Expected key.name length");
    std::copy_n(key.name_.begin(), 16, key_name);
    
    int rc = RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));
    ASSERT(rc);

    // This RELEASE_ASSERT is logically a static_assert, but we can't actually get
    // EVP_CIPHER_key_length(cipher) at compile-time
    RELEASE_ASSERT(key.aes_key_.size() == EVP_CIPHER_key_length(cipher), "");
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, key.aes_key_.data(), iv)) {
      return -1;
    }

    if (!HMAC_Init_ex(hmac_ctx, key.hmac_key_.data(), key.hmac_key_.size(), hmac, nullptr)) {
      return -1;
    }

    return 1; // success
  } else {
    // Decrypt
    bool is_enc_key = true; // first element is the encryption key
    for (const ServerContextConfig::SessionTicketKey& key : session_ticket_keys_) {
      static_assert(std::tuple_size<decltype(key.name_)>::value == 16,
                    "Expected key.name length");
      if (std::equal(key.name_.begin(), key.name_.end(), key_name)) {
        if (!HMAC_Init_ex(hmac_ctx, key.hmac_key_.data(), key.hmac_key_.size(), hmac, nullptr)) {
          return -1;
        }

        RELEASE_ASSERT(key.aes_key_.size() == EVP_CIPHER_key_length(cipher), "");
        if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, key.aes_key_.data(), iv)) {
          return -1;
        }

        // If our current encryption was not the decryption key, renew
        return is_enc_key ? 1  // success; do not renew
                          : 2; // success: renew key
      }
      is_enc_key = false;
    }

    return 0; // decryption failed
  }
}

} // namespace Ssl
} // namespace Envoy
