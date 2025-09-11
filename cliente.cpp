#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "decrypt/decrypt.hpp"
#include "encrypt/encrypt.hpp"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Numero de argumentos insuficiente\n");
        exit(1);
    }

    // Puts the RSA key in memory
    EVP_PKEY *rsaKey = loadPublicKey(argv[2]);

    // Creates a socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);

    if (inet_pton(AF_INET, argv[1], &serverAddr.sin_addr) != 1) {
        fprintf(stderr, "IP Inválido\n");
        exit(2);
    }

    // Connects to the server
    connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    // From here on can send and receive messages

    // Generates the AES key
    unsigned char aesKey[32];  // 256 bits
    if (RAND_bytes(aesKey, 32) != 1) {
        printf("Error generating AES key\n");
        return 1;
    }

    // Should send a message with an encrypted AES key
    size_t size = 0;
    unsigned char *buffer = rsaEncryptEvp(rsaKey, aesKey, 32, &size);
    send(clientSocket, buffer, size, 0);

    // Put a function to send a file divided in 4kb buffers
    // Each one must be encrypted using AES

    // Close clientSocket
    close(clientSocket);
    free(buffer);
    EVP_PKEY_free(rsaKey);
}