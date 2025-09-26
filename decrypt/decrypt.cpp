/**
 * @file decrypt.cpp
 * @brief Implements the functions used for decryption and signing in this
 * system
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

unsigned char *aesDecryptEvp(const unsigned char *key,
                             const unsigned char *encrypted, unsigned char *tag,
                             size_t msgLen, const unsigned char *iv,
                             unsigned char *decLen) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *decrypted = (unsigned char *)malloc(msgLen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        exit(1);
    };

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        exit(1);
    }

    if (!EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, msgLen)) {
        exit(1);
    }

    *decLen = len;

    // Pega o TAG de autenticação
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAGLEN,
                             (void *)tag)) {
        exit(1);
    }

    if (!EVP_DecryptFinal_ex(ctx, decrypted + len, &len)) {
        exit(1);
    }

    *decLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

unsigned char *rsaSignEvp(EVP_PKEY *key, const unsigned char *msg,
                          size_t msgLen, size_t *sigLen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "rsaSignEvp(1)\n");
        exit(1);
    }

    if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key)) {
        fprintf(stderr, "rsaSignEvp(2)\n");
        exit(1);
    }

    if (!EVP_DigestSignUpdate(ctx, msg, msgLen)) {
        fprintf(stderr, "rsaSignEvp(3)\n");
        exit(1);
    }

    if (!EVP_DigestSignFinal(ctx, NULL, sigLen)) {
        fprintf(stderr, "rsaSignEvp(4)\n");
        exit(1);
    }

    unsigned char *signature = (unsigned char *)malloc(*sigLen);

    if (!EVP_DigestSignFinal(ctx, signature, sigLen)) {
        fprintf(stderr, "rsaSignEvp(5)\n");
        exit(1);
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}

EVP_PKEY *loadPrivateKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}