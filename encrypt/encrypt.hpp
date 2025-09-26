/**
 * @file encrypt.hpp
 * @brief Describes the functions used for encryption and verification in this
 * system
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define AES_KEYLEN 32  // 256 bits
#define AES_IVLEN 12   // 96 bits (recomendado para GCM)
#define AES_TAGLEN 16  // 128 bits

/**
 * @brief Encrypts a message with RSA
 * @param[in] pubKey Public RSA key
 * @param[in] msg Message to be encrypted
 * @param[in] msgLen Length of the message
 * @param[out] encLen Variable that will contain the length of the encrypted
 * message
 * @return The encrypted message
 */
unsigned char *rsaEncryptEvp(EVP_PKEY *key, const unsigned char *msg,
                             size_t msgLen, size_t *encLen);

/**
 * @brief Encrypts a message with AES
 * @param[in] key AES key
 * @param[in] msg Message to be encrypted
 * @param[in] msgLen Length of the message to be encrypted
 * @param[in] iv The initial vector that will be used to encrypt the message
 * @param[out] tag Tag to validate integrity(must be 16 bytes)
 * @param[out] encLen Length of the encrypted message
 * @return The encrypted text
 */
unsigned char *aesEncryptEvp(const unsigned char *key, const unsigned char *msg,
                             size_t msgLen, const unsigned char *iv,
                             unsigned char *tag, size_t *encLen);

/**
 * @brief Generates a signature using RSA
 * @param[in] key RSA Public key
 * @param[in] msg Message to be verified
 * @param[in] msgLen Length of the message being
 * @param[in] sig Signature to be verified
 * @param[in] sigLen Length of the signature
 * @return 1 if msg is correct and 0 if it is incorrect
 */
int rsaVerifyEvp(EVP_PKEY *key, const unsigned char *msg, size_t msgLen,
                 const unsigned char *sig, size_t sigLen);

/**
 * @brief Loads the public key in a file to a EVP_KEY
 * @param[in] filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPublicKey(const char *filename);

#endif