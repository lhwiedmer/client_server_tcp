/**
 * @file decrypt.hpp
 * @brief Describres the functions used for decryption and signing in this
 * system
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define AES_KEYLEN 32  // 256 bits
#define AES_IVLEN 12   // 96 bits
#define AES_TAGLEN 16  // 128 bits

/**
 * @brief Decrypts a message encoded with RSA
 * @param privKey Private RSA key
 * @param encMsg Message to be decrypted
 * @param encLen Length of the encrypted message
 * @param decLen Variable that will contain the length of the actual message
 * @return The decrypted message
 */
unsigned char *rsaDecryptEvp(EVP_PKEY *privkey, const unsigned char *encMsg,
                             size_t encLen, size_t *decLen);

/**
 * @brief Encrypts a message with AES
 * @param[in] key AES key
 * @param[in] encrypted Message to be encrypted
 * @param[in] encLen Length of the message to be encrypted
 * @param[in] tag Tag to validate integrity
 * @param[in] iv The initial vector that will be used to encrypt the message
 * @param[out] decLen Length of the decrypted message
 * @return The decrypted text
 */
unsigned char *aesDecryptEvp(const unsigned char *key,
                             const unsigned char *encrypted,
                             const unsigned char *tag, size_t msgLen,
                             const unsigned char *iv, unsigned char *decLen);

/**
 * @brief Generates a signature using RSA
 * @param[in] key RSA Private key
 *
 */
unsigned char *rsaSignEvp(EVP_PKEY *key, const unsigned char *msg,
                          size_t msgLen, size_t *encLen);

/**
 * @brief Loads the private key in a file to a EVP_KEY
 * @param filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPrivateKey(const char *filename);

#endif