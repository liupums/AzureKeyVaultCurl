#include <openssl/err.h>
#include <openssl/e_os2.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY *getPKey(const unsigned char* n, const size_t nSize, const unsigned char* e, const size_t eSize)
{
    // static unsigned char n[] =
    //     "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
    //     "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
    //     "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
    //     "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
    //     "\xF5";
    // static unsigned char e[] = "\x11";

    RSA *rsa = RSA_new();
    EVP_PKEY *pk = EVP_PKEY_new();

    if (rsa == NULL || pk == NULL || !EVP_PKEY_assign_RSA(pk, rsa))
    {
        RSA_free(rsa);
        EVP_PKEY_free(pk);
        return NULL;
    }

    if (!RSA_set0_key(rsa, BN_bin2bn(n, nSize, NULL), BN_bin2bn(e, eSize, NULL), NULL))
    {
        EVP_PKEY_free(pk);
        return NULL;
    }

    return pk;
}

int pkeyEncrypt(EVP_PKEY *pkey, int paddingMode, const unsigned char *clearText, const size_t clearTextSize, unsigned char* ciperText, size_t* ciperTextSize)
{
    EVP_PKEY_CTX *ctx = NULL;
    int to_return = 0;

    if (pkey == NULL)
    {
        to_return = 1;
        goto err;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        to_return = 2;
        goto err;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, paddingMode) <= 0)
    {
        to_return = 3;
        goto err;
    }

    if (EVP_PKEY_encrypt_init(ctx) != 0)
    {
        to_return = 4;
        goto err;
    }

    if (EVP_PKEY_encrypt(ctx, ciperText, ciperTextSize, clearText, clearTextSize) <= 0)
    {
        to_return = 5;
        goto err;
    }
 err:
    EVP_PKEY_CTX_free(ctx);
    return to_return;
}