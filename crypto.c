#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return EXIT_FAILURE;
    }
}

EVP_PKEY* generate_rsa_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        handle_errors();
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handle_errors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        handle_errors();
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int public_key_to_pem(EVP_PKEY *pkey, unsigned char **out) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return EXIT_FAILURE;
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        handle_errors();
        BIO_free(bio);
        return EXIT_FAILURE;
    }
    int len = BIO_pending(bio);
    *out = malloc(len);
    if (!*out) {
        BIO_free(bio);
        return EXIT_FAILURE;
    }
    BIO_read(bio, *out, len);
    BIO_free(bio);
    return len;
}

EVP_PKEY* pem_to_public_key(unsigned char *data, int len) {
    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) handle_errors();
    BIO_free(bio);
    return pkey;
}

int rsa_encrypt(EVP_PKEY *pubkey, unsigned char *in, int in_len, unsigned char *out) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        handle_errors();
        return EXIT_FAILURE;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        handle_errors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_errors();
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, in_len) <= 0)
        handle_errors();
    if (EVP_PKEY_encrypt(ctx, out, &outlen, in, in_len) <= 0)
        handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int rsa_decrypt(EVP_PKEY *privkey, unsigned char *in, int in_len, unsigned char *out) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) {
        handle_errors();
        return EXIT_FAILURE;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handle_errors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_errors();
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, in_len) <= 0)
        handle_errors();
    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, in_len) <= 0)
        handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int generate_random_bytes(unsigned char *buf, int len) {
    if (RAND_bytes(buf, len) != 1) {
        handle_errors();
        return 0;
    }
    return 1;
}

void free_key(EVP_PKEY *pkey) {
    if (pkey) EVP_PKEY_free(pkey);
}