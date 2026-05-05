#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/select.h>

#define PORT 5555
#define BUFFER_SIZE 2048
int server_fd, client1 = -1, client2 = -1;
volatile int running = 1;

void handle_sigint(int sig) {
    printf("\nShutting down server...\n");
    running = 0;
}

void cleanup() {
    if (client1 != -1) close(client1);
    if (client2 != -1) close(client2);
    if (server_fd != -1) close(server_fd);
}

int main() {
    //настройка на сървъра
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    signal(SIGINT, handle_sigint);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    //настройка на адреса и порта
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    listen(server_fd, 2);
    printf("Server listening on port %d...\n", PORT);
    printf("Waiting for client 1...\n");
    client1 = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    printf("Client 1 connected\n");
    printf("Waiting for client 2...\n");
    client2 = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    printf("Client 2 connected\n");
    uint8_t role_initiator = 1;
    uint8_t role_responder = 0;
    send(client1, &role_initiator, 1, 0);
    send(client2, &role_responder, 1, 0);
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    //основен цикъл
    while (running) {
        FD_ZERO(&readfds);
        FD_SET(client1, &readfds);
        FD_SET(client2, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        int max_sd = client1 > client2 ? client1 : client2;
        if (STDIN_FILENO > max_sd) 
           max_sd = STDIN_FILENO;
        //обработка на вход от клиент
        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (!running) break;
            perror("select error");
            break;
        }
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            fgets(buffer, BUFFER_SIZE, stdin);
            //команда за спиране на сървъра
            if (strncmp(buffer, "quit", 4) == 0) {
                printf("Stopping server by command...\n");
                break;
            }
        }
        if (FD_ISSET(client1, &readfds)) {
            int valread = recv(client1, buffer, BUFFER_SIZE, 0);
            if (valread <= 0) break;
            send(client2, buffer, valread, 0);
        }
        if (FD_ISSET(client2, &readfds)) {
            int valread = recv(client2, buffer, BUFFER_SIZE, 0);
            if (valread <= 0) break;
            send(client1, buffer, valread, 0);
        }
    }
    cleanup();
    printf("Server stopped.\n");
    return EXIT_SUCCESS;
}