#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

EVP_PKEY* generate_rsa_key();

int public_key_to_pem(EVP_PKEY *pkey, unsigned char **out);
EVP_PKEY* pem_to_public_key(unsigned char *data, int len);

int rsa_encrypt(EVP_PKEY *pubkey,
                unsigned char *in, int in_len,
                unsigned char *out);

int rsa_decrypt(EVP_PKEY *privkey,
                unsigned char *in, int in_len,
                unsigned char *out);

int generate_random_bytes(unsigned char *buf, int len);

void free_key(EVP_PKEY *pkey);

int aes_gcm_encrypt(
    unsigned char *plaintext, int plaintext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag
);

int aes_gcm_decrypt(
    unsigned char *ciphertext, int ciphertext_len,
    unsigned char *tag,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *plaintext
);

#endif