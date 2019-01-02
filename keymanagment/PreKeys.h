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

/*
 * Changes for sZina Copyright 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef PREKEYS_H
#define PREKEYS_H

/**
 * @file PreKeys.h
 * @brief Generate and store pre-keys
 * @ingroup sZinaInternal
 * @{
 */

#include "../ratchet/crypto/DhPublicKey.h"
#include "../ratchet/crypto/DhPrivateKey.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../Constants.h"
#include "../common/DataStructures.h"

namespace zina {

    class PreKeys
    {
    public:

        /**
         * @brief Generate a one-time pre-key.
         * 
         * This functions generates one pre-key and stores it in the persistent
         * store. The store instance must be open and ready.
         * 
         * @param store The persistent store.
         * @param isSignedKey @c true if this is a signed pre-prey
         * @return a new pre-key and its id
         */
        static PreKeyDataUnique
        generateOneTime(SQLiteStoreConv& store);

        /**
         * @brief Generate a batch of one-time pre-keys.
         * 
         * This functions generates a batch of one-time pre-keys and stores them in the
         * persistent store. The store instance must be open and ready.
         * 
         * The caller should check the size of the list if it contains pre-keys.
         * The list does not contain @c nullptr pointers.
         * 
         * @param store The persistent store.
         * @param num Optional, number of pre-keys to generate, defaults to 100
         * @return List of the generated new one-time pre-keys.
         */
        static int32_t
        generateOneTimeKeys(std::list<PreKeyDataUnique>& keys, SQLiteStoreConv& store, int32_t num = NUM_PRE_KEYS);

        /**
         * @brief Generate a signed pre-key.
         *
         * This functions generates a signed pre-key and stores it in the persistent
         * store. The store instance must be open and ready.
         *
         * @param store The persistent store to store and retrieve state information.
         * @param signingKey key used to sign the generated pre-key
         * @return PreKeyData. If PreKeyData#result is @c SUCCESS then the data is valid.
         */
        static PreKeyDataUnique
        generateSigned(const DhPrivateKey &signingKey, SQLiteStoreConv& store);
    
        /**
         * @brief Verify a signed pre-key.
         *
         * This functions verifies a signed pre-key.
         *
         * @param verifyingKey The key used to verify the data and its signature
         * @param signedKey The public signed key to verify
         * @param signature The signature data
         * @return @c SUCCESS if verification was OK, error code otherwise 
         */
        static int32_t
        verifySigned(const DhPublicKey &verifyingKey, const DhPublicKey &signedKey, const std::string &signature);

    };
} // namespace sZina

/**
 * @}
 */

#endif // PREKEYS_H
