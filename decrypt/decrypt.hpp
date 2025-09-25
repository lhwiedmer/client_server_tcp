/**
 * @file decrypt.hpp
 * @brief Describres the functions used for decryption in this system
 * @author Luiz Henrique Murback Wiedmer
 * @date 2025-09-25
 */

#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

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
 * @brief Loads the private key in a file to a EVP_KEY
 * @param filename Name of the file with the private key
 * @return EVP_KEY containing the key that was in the file
 */
EVP_PKEY *loadPrivateKey(const char *filename);

#endif