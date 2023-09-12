#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <testcase-socket.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1337 

bool testcase_enabled(char *supi) {
    if (ogs_app()->tester.supi != NULL) {
        ogs_debug("TEST tester.supi: %s", ogs_app()->tester.supi);
        ogs_debug("TEST amf supi: %s", supi);
        if (strcmp(ogs_app()->tester.supi, supi) == 0 && ogs_app()->tester.enabled) {
            return true;
        }
    }
    return false;
}

void create_client_socket(int *client_socket) {
    struct sockaddr_in server_addr;

    // Create socket
    *client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Set up the server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Connect to the server
    if (connect(*client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }
}

void get_supi(char *supi){
    int client_socket;
    char server_response[21];

    // Create socket
    create_client_socket(&client_socket);

    if (recv(client_socket, server_response, sizeof(server_response), 0) == -1) {
        perror("Error receiving data from server");
        exit(EXIT_FAILURE);
    }

    //ogs_debug("TEST Server response: %s\n", server_response);
    // Close the socket
    close(client_socket);
    server_response[20] = '\0';
    strcpy(supi, server_response);
}

int send_msg_type(uint8_t type) {
    int client_socket;
    char server_response[1];
    // char server_response[1];

    // Create socket
    create_client_socket(&client_socket);


    if (send(client_socket, &type, sizeof(type), 0) == -1) {
        perror("Error sending data to server");
        exit(EXIT_FAILURE);
    }

    if (recv(client_socket, server_response, sizeof(server_response), 0) == -1) {
        perror("Error receiving data from server");
        exit(EXIT_FAILURE);
    }


    // Close the socket
    close(client_socket);
    return (int) server_response[0];
}

void modify_msg(ogs_pkbuf_t *pkbuf) {
    int client_socket;
    unsigned char server_response[pkbuf->len];

    create_client_socket(&client_socket);

    if (send(client_socket, pkbuf->data, pkbuf->len, 0) == -1) {
        perror("Error sending data to server");
        exit(EXIT_FAILURE);
    }

    // Receive data from the server
    if (recv(client_socket, server_response, sizeof(server_response), 0) == -1) {
        perror("Error receiving data from server");
        exit(EXIT_FAILURE);
    }

    ogs_debug("TEST Server response: %s\n", server_response);

    // Close the socket
    close(client_socket);
    memcpy(pkbuf->data, server_response, sizeof(server_response));
}
