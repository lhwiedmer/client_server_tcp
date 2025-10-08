/**
 * @file cliente.cpp
 * @brief Main program for the server side of the application
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "decrypt/decrypt.hpp"
#include "encrypt/encrypt.hpp"

/**
 * @brief Creates a socket and binds it to a ip address
 * @param[in] ipAddr IP address which the socket will be bound to
 * @return The created socket
 */
int createServerSocket(char *ipAddr) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);

    if (inet_pton(AF_INET, ipAddr, &serverAddr.sin_addr) != 1) {
        fprintf(stderr, "IP Inválido\n");
        exit(3);
    }

    bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    return serverSocket;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Numero de argumentos insuficiente\n");
        exit(1);
    }
    // Puts the RSA key in memory
    EVP_PKEY *rsaDecryptKey = loadPrivateKey(argv[2]);
    EVP_PKEY *rsaSignKey = loadPrivateKey(argv[3]);

    // Creates a socket
    int serverSocket = createServerSocket(argv[1]);

    // Starts listening
    listen(serverSocket, 1);

    // Accepts a request for connection
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    // From here on can send and receive messages

    // Should get a random message
    unsigned char *randStr;
    recv(clientSocket, randStr, 16, 0);
    size_t signedStrLen;
    // Sign random string
    unsigned char *signedStr =
        rsaSignEvp(rsaSignKey, randStr, 16, &signedStrLen);

    // Should get a message with an encrypted AES key
    unsigned char *buffer = (unsigned char *)malloc(1024);
    recv(clientSocket, buffer, 1024, 0);

    size_t decLen = 0;
    // Decrypt with the RSA key
    unsigned char *aesKey = rsaDecryptEvp(rsaDecryptKey, buffer, 256, &decLen);

    printf("AES Key\n");
    for (size_t i = 0; i < decLen; i++) {
        printf("%c", aesKey[i]);
    }
    printf("\n");

    // Send response that everything went right
    // uint16_t res = htons(1);
    // send(clientSocket, &res, sizeof(res), 0);

    // Close serverSocket
    close(serverSocket);
    close(clientSocket);
    free(buffer);
    EVP_PKEY_free(rsaDecryptKey);
    EVP_PKEY_free(rsaSignKey);
    free(aesKey);
}
