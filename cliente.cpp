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

/**
 * @brief Encrypts a message with RSA
 * @param pubKey Public RSA key
 * @param msg Message to be encrypted
 * @param msgLen Length of the message
 * @param encLen Variable that will contain the length of the encrypted message
 * @return The encrypted message
 */
unsigned char *rsaEncryptEvp(EVP_PKEY *pubkey, const unsigned char *msg,
                             size_t msgLen, size_t *encLen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        exit(3);
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        exit(3);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        exit(3);
    }

    // Descobrir tamanho necessário
    if (EVP_PKEY_encrypt(ctx, NULL, encLen, msg, msgLen) <= 0) {
        exit(3);
    }

    unsigned char *encrypted = (unsigned char *)malloc(*encLen);

    if (EVP_PKEY_encrypt(ctx, encrypted, encLen, msg, msgLen) <= 0) {
        exit(3);
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

/**
 * @brief Loads the public key in a file to a EVP_KEY
 * @param filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPublicKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

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

    // Close clientSocket
    close(clientSocket);
    free(buffer);
    EVP_PKEY_free(rsaKey);
}