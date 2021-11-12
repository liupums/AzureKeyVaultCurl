#ifndef OPENSSLTEST_H
#define OPENSSLTEST_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

EVP_PKEY *getPKey(const unsigned char* n, const size_t nSize, const unsigned char* e, const size_t eSize);
int pkeyEncrypt(EVP_PKEY *pkey, int paddingMode, const unsigned char *clearText, const size_t clearTextSize, unsigned char* ciperText, size_t* ciperTextSize);

#endif