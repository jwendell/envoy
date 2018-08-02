#include "common/ssl/utility.h"

#include <algorithm>

namespace Envoy {
namespace Ssl {

std::string Utility::getSerialNumberFromCertificate(X509* cert) {
  ASN1_INTEGER* serial_number = X509_get_serialNumber(cert);
  BIGNUM* num_bn(BN_new());
  ASN1_INTEGER_to_BN(serial_number, num_bn);
  char* char_serial_number = BN_bn2hex(num_bn);
  BN_free(num_bn);
  if (char_serial_number != nullptr) {
    std::string serial_number(char_serial_number);

    //FIXME: openssl is uppercase, boringssl is lowercase. So convert
    std::transform(serial_number.begin(), serial_number.end(), serial_number.begin(), ::tolower);
    
    OPENSSL_free(char_serial_number);
    return serial_number;
  }
  return "";
}

} // namespace Ssl
} // namespace Envoy
