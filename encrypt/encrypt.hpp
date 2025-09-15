/**
 * @file encrypt.hpp
 */

#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/**
 * @brief Encrypts a message with RSA
 * @param pubKey Public RSA key
 * @param msg Message to be encrypted
 * @param msgLen Length of the message
 * @param encLen Variable that will contain the length of the encrypted message
 * @return The encrypted message
 */
unsigned char *rsaEncryptEvp(EVP_PKEY *pubkey, const unsigned char *msg,
                             size_t msgLen, size_t *encLen);

/**
 * @brief Encrypts a message with AES
 * @param aesKey AES key
 * @param msg Message to be encrypted
 * @param msgLen Length of the message to be encrypted
 * @param iv The initial vector that will be used to encrypt the message
 * @param encMsgLen Length of the encrypted message
 * @return The encrypted text
 */
unsigned char *aesEncryptEvp(unsigned char *aesKey, unsigned char *msg,
                             size_t msgLen, unsigned char *iv,
                             unsigned char *encMsgLen);

/**
 * @brief Loads the public key in a file to a EVP_KEY
 * @param filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPublicKey(const char *filename);

#endif