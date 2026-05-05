//тестове написани от ai за crypto.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"
 
/* ── helpers ── */
static int passed = 0;
static int failed = 0;
 
#define TEST(name) printf("\n[TEST] %s\n", name)
#define PASS() do { printf("  PASS\n"); passed++; } while(0)
#define FAIL(msg) do { printf("  FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(cond, msg) do { if (cond) PASS(); else FAIL(msg); } while(0)
 
/* ══════════════════════════════════════════
   1. RSA ключ – генериране
   ══════════════════════════════════════════ */
static void test_rsa_keygen(void)
{
    TEST("RSA keygen връща ненулев указател");
    EVP_PKEY *k = generate_rsa_key();
    CHECK(k != NULL, "generate_rsa_key() върна NULL");
    free_key(k);
}
 
/* ══════════════════════════════════════════
   2. RSA ключ – сериализация / десериализация
   ══════════════════════════════════════════ */
static void test_pubkey_pem_roundtrip(void)
{
    TEST("Публичен ключ: PEM сериализация и обратно");
    EVP_PKEY *orig = generate_rsa_key();
    assert(orig);
 
    unsigned char *pem = NULL;
    int len = public_key_to_pem(orig, &pem);
    CHECK(len > 0, "public_key_to_pem върна <= 0");
 
    EVP_PKEY *restored = pem_to_public_key(pem, len);
    CHECK(restored != NULL, "pem_to_public_key върна NULL");
 
    free(pem);
    free_key(orig);
    free_key(restored);
}
 
/* ══════════════════════════════════════════
   3. RSA encrypt / decrypt – happy path
   ══════════════════════════════════════════ */
static void test_rsa_encrypt_decrypt(void)
{
    TEST("RSA encrypt→decrypt възстановява plaintext");
    EVP_PKEY *key = generate_rsa_key();
    assert(key);
 
    unsigned char plain[32];
    generate_random_bytes(plain, 32);
 
    unsigned char cipher[512];
    int enc_len = rsa_encrypt(key, plain, 32, cipher);
    CHECK(enc_len > 0, "rsa_encrypt върна <= 0");
 
    unsigned char out[512];
    int dec_len = rsa_decrypt(key, cipher, enc_len, out);
    CHECK(dec_len == 32, "rsa_decrypt върна грешна дължина");
    CHECK(memcmp(plain, out, 32) == 0, "Декриптираният текст не съвпада");
 
    free_key(key);
}
 
/* ══════════════════════════════════════════
   4. RSA decrypt с грешен ключ → грешка
   ══════════════════════════════════════════ */
static void test_rsa_decrypt_wrong_key(void)
{
    TEST("RSA decrypt с грешен ключ не възстановява оригиналния plaintext");
    EVP_PKEY *key1 = generate_rsa_key();
    EVP_PKEY *key2 = generate_rsa_key();
    assert(key1 && key2);
 
    unsigned char plain[32];
    generate_random_bytes(plain, 32);
 
    unsigned char cipher[512];
    int enc_len = rsa_encrypt(key1, plain, 32, cipher);
 
    unsigned char out[512];
    memset(out, 0, sizeof(out));
    int dec_len = rsa_decrypt(key2, cipher, enc_len, out);
 
    /* Грешният ключ трябва или да върне грешка (dec_len != 32)
       или да декриптира в различни данни — и двете са приемливи */
    int data_matches = (dec_len == 32) && (memcmp(plain, out, 32) == 0);
    CHECK(!data_matches, "Грешният ключ декриптира правилно — невъзможно");
 
    free_key(key1);
    free_key(key2);
}
 
/* ══════════════════════════════════════════
   5. AES-GCM – happy path
   ══════════════════════════════════════════ */
static void test_aes_gcm_roundtrip(void)
{
    TEST("AES-256-GCM encrypt→decrypt възстановява plaintext");
 
    unsigned char key[32], iv[12];
    generate_random_bytes(key, 32);
    generate_random_bytes(iv,  12);
 
    const char *msg = "Hello, secure world!";
    int msg_len = (int)strlen(msg);
 
    unsigned char cipher[256], tag[16], plain[256];
 
    int ct_len = aes_gcm_encrypt((unsigned char*)msg, msg_len,
                                 key, iv, cipher, tag);
    CHECK(ct_len == msg_len, "Ciphertext дължината е грешна");
 
    int pt_len = aes_gcm_decrypt(cipher, ct_len, tag, key, iv, plain);
    CHECK(pt_len == msg_len, "Plaintext дължината е грешна след decrypt");
    plain[pt_len] = '\0';
    CHECK(memcmp(msg, plain, msg_len) == 0, "Декриптираният текст не съвпада");
}
 
/* ══════════════════════════════════════════
   6. AES-GCM – модифициран ciphertext → грешка
   ══════════════════════════════════════════ */
static void test_aes_gcm_tampered_ciphertext(void)
{
    TEST("AES-GCM открива модификация на ciphertext (GCM tag fail)");
 
    unsigned char key[32], iv[12];
    generate_random_bytes(key, 32);
    generate_random_bytes(iv,  12);
 
    const char *msg = "Tamper me!";
    int msg_len = (int)strlen(msg);
 
    unsigned char cipher[256], tag[16], plain[256];
    int ct_len = aes_gcm_encrypt((unsigned char*)msg, msg_len,
                                 key, iv, cipher, tag);
 
    cipher[0] ^= 0xFF;  /* модифицираме 1 байт */
 
    int ret = aes_gcm_decrypt(cipher, ct_len, tag, key, iv, plain);
    CHECK(ret < 0, "Трябваше да върне -1 при модифициран ciphertext");
}
 
/* ══════════════════════════════════════════
   7. AES-GCM – модифициран tag → грешка
   ══════════════════════════════════════════ */
static void test_aes_gcm_tampered_tag(void)
{
    TEST("AES-GCM открива модификация на GCM tag");
 
    unsigned char key[32], iv[12];
    generate_random_bytes(key, 32);
    generate_random_bytes(iv,  12);
 
    const char *msg = "Tag tamper test";
    int msg_len = (int)strlen(msg);
 
    unsigned char cipher[256], tag[16], plain[256];
    aes_gcm_encrypt((unsigned char*)msg, msg_len, key, iv, cipher, tag);
 
    tag[0] ^= 0xFF;  /* модифицираме тага */
 
    int ret = aes_gcm_decrypt(cipher, msg_len, tag, key, iv, plain);
    CHECK(ret < 0, "Трябваше да върне -1 при модифициран tag");
}
 
/* ══════════════════════════════════════════
   8. AES-GCM – грешен ключ → грешка
   ══════════════════════════════════════════ */
static void test_aes_gcm_wrong_key(void)
{
    TEST("AES-GCM открива грешен ключ при decrypt");
 
    unsigned char key1[32], key2[32], iv[12];
    generate_random_bytes(key1, 32);
    generate_random_bytes(key2, 32);
    generate_random_bytes(iv,   12);
 
    const char *msg = "Wrong key test";
    int msg_len = (int)strlen(msg);
 
    unsigned char cipher[256], tag[16], plain[256];
    aes_gcm_encrypt((unsigned char*)msg, msg_len, key1, iv, cipher, tag);
 
    int ret = aes_gcm_decrypt(cipher, msg_len, tag, key2, iv, plain);
    CHECK(ret < 0, "Трябваше да върне -1 при грешен ключ");
}
 
/* ══════════════════════════════════════════
   9. AES-GCM – уникалност на два IV
   ══════════════════════════════════════════ */
static void test_iv_uniqueness(void)
{
    TEST("generate_random_bytes произвежда различни IV при два извиквания");
 
    unsigned char iv1[12], iv2[12];
    generate_random_bytes(iv1, 12);
    generate_random_bytes(iv2, 12);
 
    CHECK(memcmp(iv1, iv2, 12) != 0,
          "Два последователни IV са еднакви (изключително малко вероятно)");
}
 
/* ══════════════════════════════════════════
   10. Сесиен ключ – пълен handshake сценарий
   ══════════════════════════════════════════ */
static void test_full_session_handshake(void)
{
    TEST("Пълен сценарий: RSA key exchange + AES-GCM съобщение");
 
    /* Client A генерира ключова двойка */
    EVP_PKEY *keyA = generate_rsa_key();
    assert(keyA);
 
    /* Client A сериализира публичния ключ */
    unsigned char *pemA = NULL;
    int pemA_len = public_key_to_pem(keyA, &pemA);
    CHECK(pemA_len > 0, "Сериализацията на ключа на A е неуспешна");
 
    /* Client B получава публичния ключ на A */
    EVP_PKEY *pubA = pem_to_public_key(pemA, pemA_len);
    CHECK(pubA != NULL, "B не може да десериализира публичния ключ на A");
    free(pemA);
 
    /* Client B генерира сесиен ключ и го криптира с pubA */
    unsigned char session_key[32];
    generate_random_bytes(session_key, 32);
 
    unsigned char encrypted_key[512];
    int enc_len = rsa_encrypt(pubA, session_key, 32, encrypted_key);
    CHECK(enc_len > 0, "B не може да криптира сесийния ключ");
    free_key(pubA);
 
    /* Client A декриптира сесийния ключ */
    unsigned char decrypted_key[512];
    int dec_len = rsa_decrypt(keyA, encrypted_key, enc_len, decrypted_key);
    CHECK(dec_len == 32, "A не може да декриптира сесийния ключ");
    CHECK(memcmp(session_key, decrypted_key, 32) == 0,
          "Сесийният ключ не съвпада след декриптиране");
 
    /* B изпраща криптирано съобщение до A */
    unsigned char iv[12], cipher[256], tag[16], plain[256];
    generate_random_bytes(iv, 12);
 
    const char *msg = "Secret message from B to A";
    int msg_len = (int)strlen(msg);
 
    int ct_len = aes_gcm_encrypt((unsigned char*)msg, msg_len,
                                 session_key, iv, cipher, tag);
    CHECK(ct_len > 0, "B не може да криптира съобщението");
 
    int pt_len = aes_gcm_decrypt(cipher, ct_len, tag,
                                 decrypted_key, iv, plain);
    CHECK(pt_len == msg_len, "A получи грешна дължина на съобщението");
    plain[pt_len] = '\0';
    CHECK(memcmp(msg, plain, msg_len) == 0, "Съобщението не съвпада след E2E");
 
    free_key(keyA);
}
 
/* ══════════════════════════════════════════
   MAIN
   ══════════════════════════════════════════ */
int main(void)
{
    printf("=== Crypto unit tests ===\n");
 
    test_rsa_keygen();
    test_pubkey_pem_roundtrip();
    test_rsa_encrypt_decrypt();
    test_rsa_decrypt_wrong_key();
    test_aes_gcm_roundtrip();
    test_aes_gcm_tampered_ciphertext();
    test_aes_gcm_tampered_tag();
    test_aes_gcm_wrong_key();
    test_iv_uniqueness();
    test_full_session_handshake();
 
    printf("\n=== Резултат: %d преминати, %d неуспешни ===\n",
           passed, failed);
    return failed == 0 ? 0 : 1;
}