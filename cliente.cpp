/**
 * @file cliente.cpp
 * @brief Main program for the client side of the application
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#include "decrypt/decrypt.hpp"
#include "encrypt/encrypt.hpp"

/**
 * @brief Creates a socket and connects it to the server
 * @param[in] serverIpAddr IP address which the socket will be connected to
 * @return The created socket
 */
int createClientSocket(char *serverIpAddr) {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);

    if (inet_pton(AF_INET, serverIpAddr, &serverAddr.sin_addr) != 1) {
        fprintf(stderr, "IP Inválido\n");
        exit(2);
    }
    // Connects to the server
    connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    return clientSocket;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Numero de argumentos insuficiente\n");
        exit(1);
    }

    // Puts the RSA key in memory
    EVP_PKEY *rsaEncryptKey = loadPublicKey(argv[2]);
    EVP_PKEY *rsaSignKey = loadPrivateKey(argv[3]);

    // Creates a socket
    int clientSocket = createClientSocket(argv[1]);

    // From here on can send and receive messages

    // Generate random string
    unsigned char randStr[16];
    if (RAND_bytes(randStr, 16) != 1) {
        fprintf(stderr, "Error generating random string\n");
        exit(4);
    }

    send(clientSocket, randStr, 16, 0);

    // Generates the AES key
    unsigned char aesKey[32];  // 256 bits
    if (RAND_bytes(aesKey, 32) != 1) {
        fprintf(stderr, "Error generating AES key\n");
        exit(4);
    }

    // Should send a message with an encrypted AES key
    size_t size = 0;
    unsigned char *buffer = rsaEncryptEvp(rsaEncryptKey, aesKey, 32, &size);
    send(clientSocket, buffer, size, 0);

    // Put a function to send a file divided in 4kb buffers
    // Each one must be encrypted using AES

    // Close clientSocket
    close(clientSocket);
    free(buffer);
    EVP_PKEY_free(rsaSignKey);
    EVP_PKEY_free(rsaEncryptKey);
}