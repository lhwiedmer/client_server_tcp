/**
 * @file decrypt.cpp
 * @brief Implements the functions used for decryption in this system
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#include "decrypt.hpp"

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

EVP_PKEY *loadPrivateKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}