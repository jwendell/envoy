#include "common/ssl/bssl_wrapper.h"

int BIO_mem_contents(const BIO *bio, const uint8_t **out_contents,
                     size_t *out_len) {
  size_t length = BIO_get_mem_data((BIO *)bio, out_contents);
  *out_len = length;
  return 1;
}
