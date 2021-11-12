#ifndef BASE64_H
#define BASE64_H

void base64urlEncode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);

int base64urlDecode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);

#endif /* BASE64_H */
