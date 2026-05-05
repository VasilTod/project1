#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "crypto.h"

#define PORT 5555
#define BUFFER_SIZE 2048
// #define MSG_TEXT 1
#define MSG_PUBKEY 2
#define MSG_SESSION_KEY 3
#define MSG_SECURE 4
unsigned char session_key[32];
int session_ready = 0;
int is_initiator = 0;

typedef struct {
    int type;
    int length;
    unsigned char data[BUFFER_SIZE];
} packet_t;

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    EVP_PKEY *my_key = NULL;
    EVP_PKEY *peer_key = NULL;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }
    //свързване към сървъра
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        return EXIT_FAILURE;
    }
    printf("Connected to server\n");

    uint8_t role;
    recv(sock, &role, 1, 0);
    is_initiator = role;
    my_key = generate_rsa_key();
    if (!my_key) {
        printf("Key generation failed\n");
        return EXIT_FAILURE;
    }
    //изпращане на публичния ключ
    unsigned char *pem;
    int pem_len = public_key_to_pem(my_key, &pem);
    packet_t pkt;
    pkt.type = MSG_PUBKEY;
    pkt.length = pem_len;
    memcpy(pkt.data, pem, pem_len);
    send(sock, &pkt, sizeof(int)*2 + pem_len, 0);
    //printf("Sent public key\n");
    free(pem);
    //основен цикъл
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        int max_sd = (sock > STDIN_FILENO ? sock : STDIN_FILENO);
        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select error");
            break;
        }
        //обработка на вход от потребителя
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char buffer[BUFFER_SIZE];
            if (!fgets(buffer, BUFFER_SIZE, stdin))
                continue;
            if (!session_ready) {
                printf("Session not ready\n");
                continue;
            }
            unsigned char iv[12];
            unsigned char tag[16];
            unsigned char ciphertext[BUFFER_SIZE - 28];
            if (!generate_random_bytes(iv, 12)) {
                printf("IV generation failed\n");
                continue;
            }
            int ct_len = aes_gcm_encrypt((unsigned char*)buffer, strlen(buffer), session_key, iv, ciphertext, tag);
            if (ct_len <= 0) {
                printf("Encryption failed\n");
                continue;
            }
            packet_t pkt;
            pkt.type = MSG_SECURE;
            int offset = 0;
            memcpy(pkt.data + offset, iv, 12);
            offset += 12;
            memcpy(pkt.data + offset, tag, 16);
            offset += 16;
            memcpy(pkt.data + offset, ciphertext, ct_len);
            offset += ct_len;
            pkt.length = offset;
            send(sock, &pkt, sizeof(int)*2 + pkt.length, 0);
        }
        //получаване на данни от другия клиент
        if (FD_ISSET(sock, &readfds)) {
            packet_t pkt;
            int valread = recv(sock, &pkt, sizeof(pkt), 0);
            if (valread <= 0) {
                printf("Disconnected\n");
                break;
            }
            //получаване на публичен ключ на другия клиент
            if (pkt.type == MSG_PUBKEY) {
                peer_key = pem_to_public_key(pkt.data, pkt.length);
                if (!peer_key) {
                    printf("Failed to parse peer public key\n");
                    continue;
                }
                //printf("Received peer public key\n");
                if (is_initiator) { //инициаторът изпраща сесийния ключ
                    if (!generate_random_bytes(session_key, 32)) {
                        printf("Session key generation failed\n");
                        continue;
                    }
                    unsigned char encrypted[512];
                    int enc_len = rsa_encrypt(peer_key, session_key, 32, encrypted);
                    if (enc_len <= 0) {
                        printf("RSA encryption failed\n");
                        continue;
                    }
                    packet_t spkt;
                    spkt.type = MSG_SESSION_KEY;
                    spkt.length = enc_len;
                    memcpy(spkt.data, encrypted, enc_len);
                    send(sock, &spkt, sizeof(int)*2 + enc_len, 0);
                    session_ready = 1;
                    //printf("Session key sent (initiator)\n");
                }
            }
            //получаване на сесийния ключ
            else if (pkt.type == MSG_SESSION_KEY) {
                unsigned char decrypted[512];
                int dec_len = rsa_decrypt(my_key, pkt.data, pkt.length, decrypted);
                if (dec_len == 32) {
                    memcpy(session_key, decrypted, 32);
                    session_ready = 1;
                    printf("Session is ready\n");
                } else {
                    printf("Session key decryption failed\n");
                }
            }
            //получаване на криптирано съобщение
            else if (pkt.type == MSG_SECURE) {
                unsigned char iv[12];
                unsigned char tag[16];
                unsigned char plaintext[BUFFER_SIZE - 28];
                int offset = 0;
                memcpy(iv, pkt.data + offset, 12);
                offset += 12;
                memcpy(tag, pkt.data + offset, 16);
                offset += 16;
                int ciphertext_len = pkt.length - offset;
                int pt_len = aes_gcm_decrypt(pkt.data + offset, ciphertext_len, tag, session_key, iv,plaintext);
                if (pt_len < 0) {
                    printf("Message authentication failed\n");
                } else {
                    if (pt_len >= BUFFER_SIZE) pt_len = BUFFER_SIZE - 1;
                    plaintext[pt_len] = '\0';
                    printf("Message: %s", plaintext);
                }
            }
        }
    }
    //чистим
    free_key(my_key);
    free_key(peer_key);
    close(sock);
    return EXIT_SUCCESS;
}