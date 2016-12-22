/*
Copyright 2016 Silent Circle, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef AESCBC_H
#define AESCBC_H

#include <stdint.h>
#include <string.h>
#include <string>
#include <memory>

/**
 * @file AesCbc.h
 * @brief Function that provide AES CBC mode support with PKCS5/7 padding on encryption
 * 
 * @ingroup Zina
 * @{
 */

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

using namespace std;

namespace zina {
/**
 * @brief Encrypt data with AES CBC mode and perform PKCS5/7 padding.
 *
 * This functions takes one data chunk, padds and encrypts it with
 * AES CBC mode.
 *
 * @param key
 *    Points to the key bytes.
 * @param IV
 *    The initialization vector which must be AES_BLOCKSIZE (16) bytes.
 * @param plainText @c a std::string that contains the plaintext
 * @param crypText pointer to a @c std::string that gets the encrypted data
 * @return @c SUCCESS if encryption was OK, an error code otherwise
 */
int32_t aesCbcEncrypt(const string& key, const string& IV, const string& plainText, string* cryptText);

/**
 * @brief Decrypt data with AES CBC mode.
 *
 * This functions takes one data chunk and decrypts it with  AES CBC mode. 
 * The lenght of the data must be a multiple of AES blocksize. The function
 * does not remove any PKCS5/7 padding bytes.
 *
 * @param key
 *    Points to the key bytes.
 * @param IV
 *    The initialization vector which must be AES_BLOCKSIZE (16) bytes.
 * @param cryptText a @c std::string that contains the encrypted data
 * @param plainText pointer to a @c std::string that gets the decrypted data
 * @return @c SUCCESS if decryption was OK, an error code otherwise
 */
int32_t aesCbcDecrypt(const string& key, const string& IV, const string& cryptText, string* plainText);

bool checkAndRemovePadding(string* data);

} // namespace
#endif // AESCBC_H
