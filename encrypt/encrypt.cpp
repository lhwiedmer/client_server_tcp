#include "encrypt.hpp"

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

unsigned char *aesEncryptEvp() {}

EVP_PKEY *loadPublicKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}