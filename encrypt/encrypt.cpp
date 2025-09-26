/**
 * @file encrypt.cpp
 * @brief Implements the functions used for encryption and verification in this
 * system
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#include "encrypt.hpp"

unsigned char *rsaEncryptEvp(EVP_PKEY *key, const unsigned char *msg,
                             size_t msgLen, size_t *encLen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) {
        fprintf(stderr, "rsaEncryptEvp(1)\n");
        exit(1);
    }

    if (!EVP_PKEY_encrypt_init(ctx)) {
        fprintf(stderr, "rsaEncryptEvp(2)\n");
        exit(1);
    }

    if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)) {
        fprintf(stderr, "rsaEncryptEvp(3)\n");
        exit(1);
    }

    // Descobrir tamanho necessário
    if (!EVP_PKEY_encrypt(ctx, NULL, encLen, msg, msgLen)) {
        fprintf(stderr, "rsaEncryptEvp(4)\n");
        exit(1);
    }

    unsigned char *encrypted = (unsigned char *)malloc(*encLen);

    if (!EVP_PKEY_encrypt(ctx, encrypted, encLen, msg, msgLen)) {
        fprintf(stderr, "rsaEncryptEvp(5)\n");
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

unsigned char *aesEncryptEvp(unsigned char *key, unsigned char *msg,
                             size_t msgLen, unsigned char *iv, size_t *encLen) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *encrypted = (unsigned char *)malloc(msgLen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        exit(1);
    };

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        exit(1);
    }

    if (!EVP_EncryptUpdate(ctx, encrypted, &len, msg, msgLen)) {
        exit(1);
    }

    *encLen = len;

    if (!EVP_EncryptFinal_ex(ctx, encrypted + len, &len)) {
        exit(1);
    }

    *encLen += len;

    unsigned char *tag;

    // Pega o TAG de autenticação
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAGLEN, tag)) {
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

int rsaVerifyEvp(EVP_PKEY *key, const unsigned char *msg, size_t msgLen,
                 const unsigned char *sig, size_t sigLen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "rsaVerifyEvp(1)\n");
        exit(1);
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key)) {
        fprintf(stderr, "rsaVerifyEvp(2)\n");
        exit(1);
    }

    if (!EVP_DigestVerifyUpdate(ctx, msg, msgLen)) {
        fprintf(stderr, "rsaVerifyEvp(3)\n");
        exit(1);
    }

    int ret = EVP_DigestVerifyFinal(ctx, sig, sigLen);
    EVP_MD_CTX_free(ctx);

    if (ret == 1) {
        return 1;
    }
    if (ret == 0) {
        return 0;
    }
    fprintf(stderr, "rsaVerifyEvp(4)\n");
    exit(1);
}

EVP_PKEY *loadPublicKey(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Falha ao tentar abrir arquivo com chave publica\n");
        exit(1);
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}