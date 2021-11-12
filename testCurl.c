#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "base64.h"

#ifdef _WIN32
  #define strcasecmp _stricmp
#endif

#ifndef _WIN32
int strcat_s(char *restrict dest, int destsz, const char *restrict src)
{  
  strncat(dest, src, destsz);
  return 0;
}
#endif

static char* HexStr(const char *data, size_t len)
{
  if (data == NULL || len == 0)
  {
    return NULL;
  }

  static char hexmap[] =
      {'0', '1', '2', '3', '4', '5', '6', '7',
       '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  char* s = (char*)malloc(len * 2 + 1);
  for (size_t i = 0; i < len; ++i)
  {
    s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }

  s[len*2] = '\0'; 
  return s;
}

struct MemoryStruct_st {
  unsigned char *memory;
  size_t size;
};

typedef struct MemoryStruct_st MemoryStruct;

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  MemoryStruct *mem = (MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

static EVP_PKEY *getPKey(const unsigned char* n, const size_t nSize, const unsigned char* e, const size_t eSize)
{
    RSA *rsa = RSA_new();
    EVP_PKEY *pk = EVP_PKEY_new();

    if (rsa == NULL || pk == NULL || !EVP_PKEY_assign_RSA(pk, rsa))
    {
        RSA_free(rsa);
        EVP_PKEY_free(pk);
        return NULL;
    }

    if (!RSA_set0_key(rsa, BN_bin2bn(n, (int)nSize, NULL), BN_bin2bn(e, (int)eSize, NULL), NULL))
    {
        EVP_PKEY_free(pk);
        return NULL;
    }

    return pk;
}

static EVP_PKEY *getECPKey(int nid_curve, const unsigned char* x, const size_t xSize, const unsigned char* y, const size_t ySize)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid_curve);
    EVP_PKEY *pk = EVP_PKEY_new();

    if (ec_key == NULL || pk == NULL || !EVP_PKEY_assign_EC_KEY(pk, ec_key))
    {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pk);
        return NULL;
    }

    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

    if (!EC_KEY_set_public_key_affine_coordinates(
        ec_key,
        BN_bin2bn(x, (int)xSize, NULL),
        BN_bin2bn(y, (int)ySize, NULL)))
    {
      printf("set affine coordinatres failed\n");
      return NULL;
    }

    return pk;
}

static int
GetAccessTokenFromIMDS(MemoryStruct*  accessToken, const char* aud)
{
  CURL *curl_handle;
  CURLcode res;
 
  accessToken->memory = malloc(1);  /* will be grown as needed by the realloc above */
  accessToken->size = 0;    /* no data at this point */

  /* init the curl session */
  curl_handle = curl_easy_init();

  char imdsUrl[4*1024] = {0};
  strcat_s(imdsUrl, sizeof imdsUrl, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=");
  strcat_s(imdsUrl, sizeof imdsUrl, aud);
  /* specify URL to get */

  //  curl_easy_setopt(curl_handle, CURLOPT_URL, 
  //  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://managedhsm.azure.net");
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  curl_easy_setopt(curl_handle, CURLOPT_URL, imdsUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Metadata: true");
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)accessToken);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
      free(accessToken->memory);
      accessToken->size = 0;
      return res;
  }
   
   /*
   {
     "access_token":"",
     "client_id":"2084ae4a-2cb6-495c-8892-e8c5f942cad1",
     "expires_in":"86400",
     "expires_on":"1631680925",
     "ext_expires_in":"86399",
     "not_before":"1631594225",
     "resource":"https://managedhsm.azure.net",
     "token_type":"Bearer"
    }
  */

  struct json_object *parsed_json;
  struct json_object *atoken;
  parsed_json = json_tokener_parse(accessToken->memory);
  // printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
  json_object_object_get_ex(parsed_json, "access_token", &atoken);
  const char* accessTokenStr = json_object_get_string(atoken);
  const size_t accessTokenStrSize = strlen(accessTokenStr); 
  // printf("access token: %zu, %s\n", accessTokenStrSize , accessTokenStr);
  char *access = (char*)malloc(accessTokenStrSize + 1);
  memcpy(access, accessTokenStr, accessTokenStrSize);
  access[accessTokenStrSize] = '\0';
  // fprintf(stderr, "\n%s\n", access);

  free(accessToken->memory);
  accessToken->memory = access;
  accessToken->size = accessTokenStrSize;
  return 0;
}

static int
HsmEncrypt(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, const MemoryStruct*  clearText, MemoryStruct*  encResult)
{
  CURL *curl_handle;
  CURLcode res;
 
  MemoryStruct encryption;
  encryption.memory = malloc(1);  /* will be grown as needed by the realloc above */
  encryption.size = 0;    /* no data at this point */
  
  // const char* keyVaultUrl = "https://az400popmhsm.managedhsm.azure.net/keys/mypemrsakey/encrypt";
  char keyVaultEncUrl[4*1024] = {0};
  strcat_s(keyVaultEncUrl, sizeof keyVaultEncUrl, keyvaultUrl);
  strcat_s(keyVaultEncUrl, sizeof keyVaultEncUrl, "/encrypt");
  if (apiVersion != NULL)
  {
     strcat_s(keyVaultEncUrl, sizeof keyVaultEncUrl, "?");
     strcat_s(keyVaultEncUrl, sizeof keyVaultEncUrl, apiVersion);
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultEncUrl);
  
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4*1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&encryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* create json object for post */
  json_object *json; 
  json = json_object_new_object();

  /* build post data
    {
        "alg": "RSA1_5",
        "value": "5ka5IVsnGrzufA"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(clearText->memory, clearText->size, NULL, &outputLen);
  if (outputLen <= 0)
  {
    printf("could not encode\n");
  }
  
  printf("encode size %zu\n", outputLen);
  unsigned char* content = (unsigned char*)malloc(outputLen);
  base64urlEncode(clearText->memory, clearText->size, content, &outputLen);
  printf("\n%s\n", content);

  json_object_object_add(json, "alg", json_object_new_string("RSA1_5"));
  json_object_object_add(json, "value", json_object_new_string(content));

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      free(encryption.memory);
      encryption.size = 0;
      return res;
  }
   
  struct json_object *parsed_json;
  parsed_json = json_tokener_parse(encryption.memory);
  printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

  struct json_object *ciperText;
  json_object_object_get_ex(parsed_json, "value", &ciperText);
  const char* value = json_object_get_string(ciperText);
  const size_t valueSize = strlen(value);
  printf("value[%zu] from json %s\n", valueSize, value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char*)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
      printf("decode size %zu\n", outputLen);
      unsigned char* result = (unsigned char*)malloc(outputLen);
      base64urlDecode((const unsigned char*)value, strlen(value), result, &outputLen);
      encResult->memory = result;
      encResult->size = outputLen;

      char* hexstr = HexStr(result, outputLen);
      printf("\n%s\n", hexstr);
      free(hexstr);
  }
  else
  {
    printf("decode error %d\n", decodeErr);
  }

  json_object_put(parsed_json);
  free(encryption.memory);
  return 0;
}

static int
HsmDecrypt(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, const MemoryStruct*  ciperText, MemoryStruct*  decryptedText)
{
  CURL *curl_handle;
  CURLcode res;
 
  MemoryStruct decryption;
  decryption.memory = malloc(1);  /* will be grown as needed by the realloc above */
  decryption.size = 0;    /* no data at this point */
  
  // const char* keyVaultUrl = "https://az400popmhsm.managedhsm.azure.net/keys/mypemrsakey/decrypt";
  char keyVaultDecUrl[4*1024] = {0};
  strcat_s(keyVaultDecUrl, sizeof keyVaultDecUrl, keyvaultUrl);
  strcat_s(keyVaultDecUrl, sizeof keyVaultDecUrl, "/decrypt");
  if (apiVersion != NULL)
  {
     strcat_s(keyVaultDecUrl, sizeof keyVaultDecUrl, "?");
     strcat_s(keyVaultDecUrl, sizeof keyVaultDecUrl, apiVersion);
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultDecUrl);
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4*1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&decryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* create json object for post */
  json_object *json; 
  json = json_object_new_object();

  /* build post data
    {
        "alg": "RSA1_5",
        "value": "cipher"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(ciperText->memory, ciperText->size, NULL, &outputLen);
  if (outputLen <= 0)
  {
    printf("could not encode\n");
  }
  
  printf("encode size %zu\n", outputLen);
  unsigned char* result = (unsigned char*)malloc(outputLen);
  base64urlEncode(ciperText->memory, ciperText->size, result, &outputLen);
  printf("\n%s\n", result);


  json_object_object_add(json, "alg", json_object_new_string("RSA1_5"));
  json_object_object_add(json, "value", json_object_new_string(result));

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  free(result);

  if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      free(decryption.memory);
      decryption.size = 0;
      return res;
  }
   
  struct json_object *parsed_json;
  parsed_json = json_tokener_parse(decryption.memory);
  printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

  struct json_object *clearText;
  json_object_object_get_ex(parsed_json, "value", &clearText);
  const char* value = json_object_get_string(clearText);
  const size_t valueSize = strlen(value);
  printf("value[%zu] from json %s\n", valueSize, value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char*)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
      printf("decode size %zu\n", outputLen);
      unsigned char* result = (unsigned char*)malloc(outputLen);
      base64urlDecode((const unsigned char*)value, strlen(value), result, &outputLen);
      decryptedText->memory = result;
      decryptedText->size = outputLen;
  }
  else
  {
    printf("decode error %d\n", decodeErr);
  }

  json_object_put(parsed_json);
  free(decryption.memory);
  return 0;
}

static int
HsmSign(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, const char* alg, const MemoryStruct*  hashText, MemoryStruct*  signatureText)
{
  CURL *curl_handle;
  CURLcode res;
 
  MemoryStruct signature;
  signature.memory = malloc(1);  /* will be grown as needed by the realloc above */
  signature.size = 0;    /* no data at this point */
  
  // const char* keyVaultUrl = "https://az400popmhsm.managedhsm.azure.net/keys/mypemrsakey/sign";
  char keyVaultSignUrl[4*1024] = {0};
  strcat_s(keyVaultSignUrl, sizeof keyVaultSignUrl, keyvaultUrl);
  strcat_s(keyVaultSignUrl, sizeof keyVaultSignUrl, "/sign");
  if (apiVersion != NULL)
  {
     strcat_s(keyVaultSignUrl, sizeof keyVaultSignUrl, "?");
     strcat_s(keyVaultSignUrl, sizeof keyVaultSignUrl, apiVersion);
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultSignUrl);
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4*1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);
  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&signature));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* create json object for post */
  json_object *json; 
  json = json_object_new_object();

  /* build post data
    {
        "alg": "PS256",
        "value": "hash value"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(hashText->memory, hashText->size, NULL, &outputLen);
  if (outputLen <= 0)
  {
    printf("could not encode\n");
  }
  
  printf("\n encode size %zu\n", outputLen);
  unsigned char* result = (unsigned char*)malloc(outputLen);
  base64urlEncode(hashText->memory, hashText->size, result, &outputLen);
  printf("\n%s\n", result);


  json_object_object_add(json, "alg", json_object_new_string(alg));
  json_object_object_add(json, "value", json_object_new_string(result));

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  free(result);

  if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      free(signature.memory);
      signature.size = 0;
      return res;
  }
   
  struct json_object *parsed_json;
  parsed_json = json_tokener_parse(signature.memory);
  printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

  struct json_object *signedText;
  json_object_object_get_ex(parsed_json, "value", &signedText);
  const char* value = json_object_get_string(signedText);
  const size_t valueSize = strlen(value);
  printf("value[%zu] from json %s\n", valueSize, value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char*)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
      printf("decode size %zu\n", outputLen);
      unsigned char* result = (unsigned char*)malloc(outputLen);
      base64urlDecode((const unsigned char*)value, strlen(value), result, &outputLen);
      signatureText->memory = result;
      signatureText->size = outputLen;
  }
  else
  {
    printf("decode error %d\n", decodeErr);
  }

  json_object_put(parsed_json);
  free(signature.memory);
  return 0;
}

int VerifyRSAEncryptDecrypt(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, EVP_PKEY *pkey)
{
  MemoryStruct clearText;
  clearText.memory = malloc(4);
  clearText.size = 4;
  clearText.memory[0] = 0x55;
  clearText.memory[1] = 0x55;
  clearText.memory[2] = 0xaa;
  clearText.memory[3] = 0xaa;
  
  size_t ciperTextSize = 0;
  unsigned char* ciperText;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
  EVP_PKEY_encrypt_init(ctx); 
  if (EVP_PKEY_encrypt(ctx, NULL, &ciperTextSize, clearText.memory, clearText.size) == 1)
  {
    ciperText = malloc(ciperTextSize);
    EVP_PKEY_encrypt(ctx, ciperText, &ciperTextSize, clearText.memory, clearText.size);

    char* hexstr = HexStr(ciperText, ciperTextSize);
    printf("pkeyEncrypt result: \n%s\n", hexstr);
    free(hexstr);
    
    printf("try to decrypt\n");
    MemoryStruct encResult;
    encResult.memory = ciperText;
    encResult.size = ciperTextSize;

    MemoryStruct result;
    HsmDecrypt(keyvaultUrl, apiVersion,  accessToken, &encResult, &result);
    
    hexstr = HexStr(result.memory, result.size);
    printf("\n%s\n", hexstr);
    free(hexstr);
    
    if (memcmp( clearText.memory, result.memory, clearText.size) == 0)
    {
      printf("\nEncrypt/Decrypt Verified successfully\n");
    }
    else
    {
      printf("\nEncrypt/Decrypt Failed\n");
    }

    free(result.memory);
    free(ciperText);
  }
  else
  {
    printf("failed to pkeyEncrypt\n");
  }

  EVP_PKEY_CTX_free(ctx);

  return 0;
}
/*
hashAlg SHA256, SHA1 etc
*/
int GetHash(const char* hashAlg, const MemoryStruct*  message, MemoryStruct*  hashResult)
{
  OpenSSL_add_all_algorithms();

  //const EVP_MD *hashptr = EVP_get_digestbyname("SHA256");
  const EVP_MD *md = EVP_get_digestbyname(hashAlg);
  if (!md)
  {
    printf("hash algo not supported: %s\n", hashAlg);
    return 1;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  int md_len;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  EVP_DigestUpdate(mdctx, message->memory, message->size);
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);

  hashResult->memory = malloc(md_len);
  hashResult->size = md_len;
  memcpy(hashResult->memory, md_value, md_len);

  return 0;
}

int VerifyRSASignature(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, EVP_PKEY *verify_key)
{
  int res = 0; // 0 means failed
  const char* alg = "PS256";
  MemoryStruct message;
  MemoryStruct messageHash;
  message.memory = malloc(4);
  message.size = 4;
  message.memory[0] = 0x55;
  message.memory[1] = 0x55;
  message.memory[2] = 0xaa;
  message.memory[3] = 0xaa;

  GetHash("sha256", &message, &messageHash);
  int i;
  printf("hash size=%zu\n", messageHash.size);
  for (i = 0; i < messageHash.size; ++i)
      printf("%02x", messageHash.memory[i]);

  MemoryStruct signatureText;
  HsmSign(keyvaultUrl, apiVersion, accessToken, alg, &messageHash, &signatureText);

  EVP_PKEY_CTX *ctx;
  ctx = EVP_PKEY_CTX_new(verify_key, NULL /* no engine */);
  if (!ctx)
  {
    printf("could not create EVP_PKEY_CTX_new\n");
    goto err;
  }

  if (EVP_PKEY_verify_init(ctx) <= 0)
  {
    printf("could not create EVP_PKEY_verify_init\n");
    goto err;
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
  {
    printf("could not set padding RSA_PKCS1_PSS_PADDING\n");
    goto err;
  }

  if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
  {
    printf("could not set signature md EVP_sha256\n");
    goto err;
  }

  /* Perform operation */
  res = EVP_PKEY_verify(ctx, signatureText.memory, signatureText.size, messageHash.memory, messageHash.size);
  if (res == 1)
  {
    printf("Successfully verified signature\n");
  }
  else
  {
    printf("Failed to verify signature\n");
  }

err:
  free(message.memory);
  free(messageHash.memory);
  EVP_PKEY_CTX_free(ctx);
  return res;
}

int VerifyEccASignature(const char* keyvaultUrl, const char* apiVersion, const MemoryStruct*  accessToken, EVP_PKEY *verify_key)
{
  // https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
  // ES256	ECDSA using P-256 and SHA-256, as described in https://tools.ietf.org/html/rfc7518.
  const char* alg = NULL;
  const char* hashAlgo = NULL;

  /* Perform operation */
  EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(verify_key);
  if (ecKey == NULL)
  {
    printf("ecKey is null\n");
    return 0;
  }

  const EC_GROUP* ec_group = EC_KEY_get0_group(ecKey);
  if (ec_group == NULL)
  {
    printf("ec_group is null\n");
    return 0;
  }

  int nid_crv = EC_GROUP_get_curve_name(ec_group);
  if (nid_crv == NID_X9_62_prime256v1)
  {
    alg = "ES256";
    hashAlgo = "sha256";
  }
  else if (nid_crv == NID_secp256k1)
  {
    alg = "ES256K";
    hashAlgo = "sha256";
  }
  else if (nid_crv == NID_secp384r1)
  {
    alg = "ES384";
    hashAlgo = "sha384";
  }
  else if (nid_crv == NID_secp521r1)
  {
    alg = "ES512";
    hashAlgo = "sha512";
  }
  else
  {
      printf("curve not supported: %d\n", nid_crv);
      goto err;      
  }
  printf("ecKey curve[%d] %s\n", nid_crv, alg);

  int res = 0; // 0 means failed
  MemoryStruct message;
  MemoryStruct messageHash;
  message.memory = malloc(4);
  message.size = 4;
  message.memory[0] = 0x55;
  message.memory[1] = 0x55;
  message.memory[2] = 0xaa;
  message.memory[3] = 0xaa;

  GetHash(hashAlgo, &message, &messageHash);
  int i;
  printf("hash size=%zu\n", messageHash.size);
  for (i = 0; i < messageHash.size; ++i)
      printf("%02x", messageHash.memory[i]);
  printf("\n=== hash  ===\n");

  MemoryStruct signatureText;
  HsmSign(keyvaultUrl, apiVersion, accessToken, alg, &messageHash, &signatureText);

  // https://stackoverflow.com/questions/17269238/ecdsa-signature-length
  int siglen = ECDSA_size(ecKey);
  printf("sig len [%d], and actual sig len [%zu]\n", siglen, signatureText.size);

  ECDSA_SIG *sig = ECDSA_SIG_new();
  int rSize = signatureText.size / 2;
  int sSize = rSize;
  ECDSA_SIG_set0(sig,
      BN_bin2bn(signatureText.memory, rSize, NULL),
      BN_bin2bn(signatureText.memory + rSize, sSize, NULL));

  res = ECDSA_do_verify(messageHash.memory, messageHash.size, sig, ecKey);
  if (res == 1)
  {
    printf("Successfully verified signature\n");
  }
  else if (res == 0)
  {
    printf("invalid signature\n");
  }else
  {
    ERR_print_errors_fp(stderr);
  }

err:
  free(message.memory);
  free(messageHash.memory);
  return res;
}


EVP_PKEY*
HsmGetKey(const char* keyvaultUrl, const char* apiVersion,  const MemoryStruct*  accessToken)
{
  CURL *curl_handle;
  CURLcode res;
  EVP_PKEY* retPKey = NULL;
  /*RSA (N,E)*/
  unsigned char* pkeyN = NULL;
  size_t pkeyNSize = 0;

  unsigned char* pkeyE = NULL;
  size_t pkeyESize = 0;

  /*EC (X,Y)*/
  unsigned char* pkeyX = NULL;
  size_t pkeyXSize = 0;

  unsigned char* pkeyY = NULL;
  size_t pkeyYSize = 0;

  MemoryStruct keyInfo;
  keyInfo.memory = malloc(1);  /* will be grown as needed by the realloc above */
  keyInfo.size = 0;    /* no data at this point */
  

  /* init the curl session */
  curl_handle = curl_easy_init();

  char KeyVaultGetUrl[4*1024] = {0};
  /* specify URL to get */
  if (apiVersion != NULL)
  {
     strcat_s(KeyVaultGetUrl, sizeof KeyVaultGetUrl, keyvaultUrl);
     strcat_s(KeyVaultGetUrl, sizeof KeyVaultGetUrl, "?");
     strcat_s(KeyVaultGetUrl, sizeof KeyVaultGetUrl, apiVersion);
     curl_easy_setopt(curl_handle, CURLOPT_URL, KeyVaultGetUrl);
  }
  else
  {
     curl_easy_setopt(curl_handle, CURLOPT_URL, keyvaultUrl);
  }
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4*1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&keyInfo));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "GET");

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      free(keyInfo.memory);
      keyInfo.size = 0;
      return retPKey;
  }
   
  struct json_object *parsed_json;
  parsed_json = json_tokener_parse(keyInfo.memory);
  // printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

  free(keyInfo.memory);

  struct json_object *keyMaterial;
  json_object_object_get_ex(parsed_json, "key", &keyMaterial);

  struct json_object *jKeyType;
  json_object_object_get_ex(keyMaterial, "kty", &jKeyType);
  const char* keyType = json_object_get_string(jKeyType);
  if (keyType == NULL)
  {
    printf("no kty defined\n");
    printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    return NULL;
  }

  if (strcasecmp(keyType, "EC-HSM") == 0 || strcasecmp(keyType, "EC") ==0)
  {
    struct json_object *jKeyCrv;
    json_object_object_get_ex(keyMaterial, "crv", &jKeyCrv);
    const char* crv = json_object_get_string(jKeyCrv);
    if (crv == NULL)
    {
      printf("crv is not defined\n");
      goto cleanup;    
    }

    int nid_curve;
    /*
    P-256: The NIST P-256 elliptic curve, AKA SECG curve SECP256R1.
    P-384: The NIST P-384 elliptic curve, AKA SECG curve SECP384R1.
    P-521: The NIST P-521 elliptic curve, AKA SECG curve SECP521R1.
    P-256K: The SECG SECP256K1 elliptic curve.
    */
    if (strcasecmp(crv, "P-256") == 0)
    {
      nid_curve = NID_X9_62_prime256v1; // https://stackoverflow.com/questions/41950056/openssl1-1-0-b-is-not-support-secp256r1openssl-ecparam-list-curves
    }
    else if (strcasecmp(crv, "P-256K") == 0)
    {
      nid_curve = NID_secp256k1;
    }
    else if (strcasecmp(crv, "P-384") == 0)
    {
      nid_curve = NID_secp384r1;
    }
    else if (strcasecmp(crv, "P-521") == 0)
    {
      nid_curve = NID_secp521r1;
    }
    else
    {
      printf("curve not supported: %s\n", crv);
      goto cleanup;      
    }

    fprintf(stderr, "curve [%s], nid [%d]\n", crv, nid_curve);
    struct json_object *jKeyX;
    struct json_object *jKeyY;
    json_object_object_get_ex(keyMaterial, "x", &jKeyX);
    json_object_object_get_ex(keyMaterial, "y", &jKeyY);
    const char* xValue = json_object_get_string(jKeyX);
    const char* yValue = json_object_get_string(jKeyY);

    size_t outputLen = 0;

    int decodeErr = base64urlDecode((const unsigned char*)xValue, strlen(xValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
        pkeyX = (unsigned char*)malloc(outputLen);
        pkeyXSize = outputLen;
        base64urlDecode((const unsigned char*)xValue, strlen(xValue), pkeyX, &outputLen);
    }
    else
    {
      printf("decode X error %d\n", decodeErr);
      goto cleanup;
    }

    outputLen = 0;
    decodeErr = base64urlDecode((const unsigned char*)yValue, strlen(yValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
        pkeyY = (unsigned char*)malloc(outputLen);
        pkeyYSize = outputLen;
        base64urlDecode((const unsigned char*)yValue, strlen(yValue), pkeyY, &outputLen);
    }
    else
    {
      printf("decode E error %d\n", decodeErr);
      goto cleanup;
    }

    fprintf(stderr, "x [%zu], y [%zu]\n", pkeyXSize, pkeyYSize);
    retPKey = getECPKey(nid_curve, pkeyX, pkeyXSize, pkeyY, pkeyYSize);
  }
  else if (strcasecmp(keyType, "RSA-HSM") == 0 || strcasecmp(keyType, "RSA") == 0)
  {
    struct json_object *jKeyN;
    struct json_object *jKeyE;
    json_object_object_get_ex(keyMaterial, "n", &jKeyN);
    json_object_object_get_ex(keyMaterial, "e", &jKeyE);
    const char* nValue = json_object_get_string(jKeyN);
    const char* eValue = json_object_get_string(jKeyE);
    size_t outputLen = 0;
    int decodeErr = base64urlDecode((const unsigned char*)nValue, strlen(nValue), NULL, &outputLen);

    if (!decodeErr && outputLen > 0)
    {
        pkeyN = (unsigned char*)malloc(outputLen);
        pkeyNSize = outputLen;
        base64urlDecode((const unsigned char*)nValue, strlen(nValue), pkeyN, &outputLen);
    }
    else
    {
      printf("decode N error %d\n", decodeErr);
      goto cleanup;
    }

    outputLen = 0;
    decodeErr = base64urlDecode((const unsigned char*)eValue, strlen(eValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
        pkeyE = (unsigned char*)malloc(outputLen);
        pkeyESize = outputLen;
        base64urlDecode((const unsigned char*)eValue, strlen(eValue), pkeyE, &outputLen);
    }
    else
    {
      printf("decode E error %d\n", decodeErr);
      goto cleanup;
    }

    retPKey = getPKey(pkeyN, pkeyNSize, pkeyE, pkeyESize);
  }
  else
  {
    printf("kty [%s] not supported\n", keyType);
    printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    return NULL;
  }

cleanup:
  if (pkeyN) free(pkeyN);
  if (pkeyE) free(pkeyE);
  if (pkeyX) free(pkeyX);
  if (pkeyY) free(pkeyY);
  json_object_put(parsed_json);
  return retPKey;
}

int main(void)
{
  const char* HSMKeyVaultName = "az400popmhsm3";
  const char* HSMRsaKeyName="testvmmhsm";
  const char* HSMAud = "https://managedhsm.azure.net";

  char HsmKeyVaultUrl[4*1024] = {0};
  strcat_s(HsmKeyVaultUrl, sizeof HsmKeyVaultUrl, "https://");
  strcat_s(HsmKeyVaultUrl, sizeof HsmKeyVaultUrl, HSMKeyVaultName);
  strcat_s(HsmKeyVaultUrl, sizeof HsmKeyVaultUrl, ".managedhsm.azure.net/keys/");
  strcat_s(HsmKeyVaultUrl, sizeof HsmKeyVaultUrl, HSMRsaKeyName);
  
  curl_global_init(CURL_GLOBAL_ALL);

  MemoryStruct accessToken;
  GetAccessTokenFromIMDS(&accessToken, HSMAud);
  printf("\n==test get rsa key===\n");
  EVP_PKEY* rsaKey = HsmGetKey(HsmKeyVaultUrl, NULL/*apiVersion*/, &accessToken);
  printf("\n==test hsm rsa encrypt and decrypt===\n");
  VerifyRSAEncryptDecrypt(HsmKeyVaultUrl, NULL, &accessToken, rsaKey);
  printf("\n==test hsm rsa sign===\n");
  VerifyRSASignature(HsmKeyVaultUrl, NULL, &accessToken, rsaKey);

  const char* HSMEcKeyName="ecckey";
  char HsmKeyVaultEcUrl[4*1024] = {0};
  strcat_s(HsmKeyVaultEcUrl, sizeof HsmKeyVaultEcUrl, "https://");
  strcat_s(HsmKeyVaultEcUrl, sizeof HsmKeyVaultEcUrl, HSMKeyVaultName);
  strcat_s(HsmKeyVaultEcUrl, sizeof HsmKeyVaultEcUrl, ".managedhsm.azure.net/keys/");
  strcat_s(HsmKeyVaultEcUrl, sizeof HsmKeyVaultEcUrl, HSMEcKeyName);

  printf("\n==test get Ecc key===\n");
  EVP_PKEY* eccKey = HsmGetKey(HsmKeyVaultEcUrl, NULL,  &accessToken);
  printf("\n==test hsm Ecc sign===\n");
  VerifyEccASignature(HsmKeyVaultEcUrl, NULL, &accessToken, eccKey);

  printf("\n===Test key vault===\n");
  const char* KeyVaultName = "akvforopensslengine";
  const char* RsaKeyName="akvrsakey";
  const char* Aud = "https://vault.azure.net";
  const char* ApiVersion = "api-version=7.2";
  char KeyVaultUrl[4*1024] = {0};
  strcat_s(KeyVaultUrl, sizeof KeyVaultUrl, "https://");
  strcat_s(KeyVaultUrl, sizeof KeyVaultUrl, KeyVaultName);
  strcat_s(KeyVaultUrl, sizeof KeyVaultUrl, ".vault.azure.net/keys/");
  strcat_s(KeyVaultUrl, sizeof KeyVaultUrl, RsaKeyName);
   
  MemoryStruct akvAccessToken;
  GetAccessTokenFromIMDS(&akvAccessToken, Aud);
  printf("\n==test get rsa key===\n");
  EVP_PKEY* akvRsaKey = HsmGetKey(KeyVaultUrl, ApiVersion, &akvAccessToken);
  printf("\n==test rsa encrypt and decrypt===\n");
  VerifyRSAEncryptDecrypt(KeyVaultUrl,ApiVersion, &akvAccessToken, akvRsaKey);
  printf("\n==test rsa sign===\n");
  VerifyRSASignature(KeyVaultUrl, ApiVersion,  &akvAccessToken, akvRsaKey);

  // /* we are done with libcurl, so clean it up */
  curl_global_cleanup();

  return 0;
}
