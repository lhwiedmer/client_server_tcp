#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Decrypts a message encoded with RSA
 * @param privKey Private RSA key
 * @param encMsg Message to be decrypted
 * @param encLen Length of the encrypted message
 * @param decLen Variable that will contain the length of the actual message
 * @return The decrypted message
 */
unsigned char *rsaDecryptEvp(EVP_PKEY *privkey, const unsigned char *encMsg,
                             size_t encLen, size_t *decLen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) exit(4);

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        exit(4);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        exit(4);
    }

    // Descobrir tamanho necessário
    if (EVP_PKEY_decrypt(ctx, NULL, decLen, encMsg, encLen) <= 0) {
        exit(4);
    }

    unsigned char *decrypted = (unsigned char *)malloc(*decLen);

    if (EVP_PKEY_decrypt(ctx, decrypted, decLen, encMsg, encLen) <= 0) {
        exit(4);
    }

    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

/**
 * @brief Loads the private key in a file to a EVP_KEY
 * @param filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPrivateKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

/**
 * @brief Creates a socket and binds it to a ip address
 * @param ipAddr IP address which the socket will be bound to
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
    EVP_PKEY *rsaKey = loadPrivateKey(argv[2]);

    // Creates a socket
    int serverSocket = createServerSocket(argv[1]);

    // Starts listening
    listen(serverSocket, 1);

    // Accepts a request for connection
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    // From here on can send and receive messages
    // Should get a message with an encrypted AES key
    unsigned char *buffer = (unsigned char *)malloc(1024);
    recv(clientSocket, buffer, 1024, 0);

    size_t decLen = 0;
    // Decrypt with the RSA key
    unsigned char *aesKey = rsaDecryptEvp(rsaKey, buffer, 256, &decLen);

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
    EVP_PKEY_free(rsaKey);
    free(aesKey);
}
