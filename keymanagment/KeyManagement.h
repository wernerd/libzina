//
// Created by wdi on 21.06.18.
//

#ifndef ZINA_KEYMANAGEMENT_H
#define ZINA_KEYMANAGEMENT_H

/**
 * @file
 * @brief Functions to manage keys, update database and call key server provisioning.
 * @ingroup Zina
 * @{
 *
 * 
 */
#include <cstdint>
#include <string>

#include "../ratchet/crypto/DhKeyPair.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "PreKeys.h"
#include "KeyProvisioningServerApi.h"

namespace zina {

    class ChatMain;            // Forward declaration to avoid circle

    class KeyManagement {

    public:
        /**
         * @brief Create the initial set of keys.
         *
         * This ised upon start of the application and if the application needs to setup a new _local_
         * user/device combination. Thus an application usually calls this function only once.
         *
         * The function creates a defined number of one-time pre-keys, a signed pre key and then stores
         * these keys in the database and call the key provisioning server to update/store the keys.
         *
         * @param [in] userId The user identifier
         * @param [in] deviceId The key bundle belongs to this user's device
         * @param [in] identity The user's long term identity key, public data
         * @param serverApi The server API implementation, stores/manages key bundles with server
         * @param store Database to store the generated keys
         * @return @c SUCCESS or a negative error code
         *
         * @see common/Constants.h for defined number of initial one-time pre-keys
         */
        static int32_t createInitialSet(const std::string& userId,
                                        const std::string& deviceId,
                                        const zina::DhKeyPair& identity,
                                        KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store);

        /**
         * @brief Generates new pre-key, adds to existing keys and updates list on the server.
         *
         * @param [in] num Number of pre-keys to add.
         * @param [in] userId The user identifier
         * @param [in] deviceId The key bundle belongs to this user's device
         * @param [in] identity The user's long term identity key, public data
         * @param serverApi The server API implementation, stores/manages key bundles with server
         * @param store Database to store the generated keys
         * @return @c SUCCESS or SQL error code
         */
        static int32_t
        addNewPreKeys(int32_t num,
                      const std::string& userId,
                      const std::string& deviceId,
                      const DhPublicKey& identity,
                      KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store);

        /**
         * @brief Generates and add a new signed pre-key to database and updates list on the server.
         *
         * The function also performs house keeping for the signed pre-keys: keep only the three newest
         * signed pre-keys.
         *
         * @param [in] userId The user identifier
         * @param [in] deviceId The key bundle belongs to this user's device
         * @param [in] identity The user's long term identity key, public data
         * @param serverApi The server API implementation, stores/manages key bundles with server
         * @param store Database to store the generated keys
         * @return @c SUCCESS or SQL error code
         */
        static int32_t
        addSignedPreKey(const std::string& userId,
                        const std::string& deviceId,
                        const DhKeyPair& identity,
                        KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store);
        /**
         * @brief Get a pre-key from database, can be a one-time or a signed pre-key.
         *
         * @param keyId Key id of the key to read
         * @param store The persistent store.
         * @return PreKeyData. If PreKeyData#result is @c SUCCESS then the data is valid
         */
        static PreKeyDataUnique
        getOneTimeFromDb(int32_t keyId, SQLiteStoreConv &store);

        /**
         * @brief Remove a pre-key from database, can be a one-time or a signed pre-key.
         *
         * @param keyId Key id of the key to read
         * @param store The persistent store.
         * @return @c SUCCESS or some error code (< 0)
         */
        static int32_t
        removeOneTimeFromDb(int32_t keyId, SQLiteStoreConv &store);

        /**
         * @brief Get all one-time pre-keys from database.
         *
         * The list may be empty if either no key data found or the key data was
         * not correct (data corrupt).
         *
         * @param keyList A list of PreKeyDataUnique that gets the key data
         * @param store The persistent store to retrieve key data.
         * @return @c SUCCESS or an error code.
         */
        static int32_t
        getAllOneTimeFromDb(std::list<PreKeyDataUnique>& keyList, SQLiteStoreConv& store);

        /**
         * @brief Get the number of available one-time pre-keys that are available on the server.
         *
         * @param userId The user's identification, for example unique id, chat address, etc
         * @param deviceId If multi-device feature is supported then this defines the specific device of the user. If the
         *                 feature is not supported the parameter should be an empty string
         * @param serverApi The server API implementation, stores/manages key bundles with server
         *
         * @return Number of available keys or @c GENERIC_ERROR in case the number cannot be determined.
         */
        static int32_t
        getNumberAvailableKeysOnServer(const std::string& userId, const std::string& deviceId, KeyProvisioningServerApi& serverApi)
        {
                return serverApi.getNumberAvailableKeysOnServer(userId, deviceId);
        }

        /**
         * @brief Get all signed pre-keys from database.
         *
         * The list may be empty if either no key data found or the key data was
         * not correct (data corrupt).
         *
         * @param keyList A list of PreKeyDataUnique that gets the key data
         * @param store The persistent store to retrieve key data.
         * @return @c SUCCESS or an error code.
         */
        static int32_t
        getAllSignedFromDb(std::list<PreKeyDataUnique>& keyList, SQLiteStoreConv& store);

        /**
         * @brief Get a new key bundle of a user/device id combination from key server
         *
         * The list may be empty if either no key data found or the key data was
         * not correct (data corrupt).
         *
         * @param [in] userId The user identifier
         * @param [in] deviceId The key bundle belongs to this user's device
         * @param serverApi The server API implementation, stores/manages key bundles with server
         * @return @c pointer to a key bundle structure or nullptr if now key bundle was available
         */
        static KeyBundleUnique
        getKeyBundleFromServer(const std::string& userId, const std::string& deviceId, KeyProvisioningServerApi& serverApi)
        {
                return serverApi.getKeyBundle(userId, deviceId);
        }

    private:
        /**
         * @brief Read key data from database and update the lists on server.
         *
         * The function also performs house keeping for the signed pre-keys: keep only the three newest
         * signed pre-keys.
         *
         * @param [in] userId The user identifier
         * @param [in] deviceId The key bundle belongs to this user's device
         * @param [in] identity The user's long term identity key, public data
         * @param [in] newOneTimeKeys Pointer to list of new one time keys, may be an empty list or nullptr
         * @param [in] newSignedKey Pointer to new signed key, may be nullptr
         * @param serverApi The server API implementation, stores/manages key bundles with server
         * @param store Database to store the generated keys
         * @return @c SUCCESS or SQL error code
         */
        static int32_t
        updatePreKeys(const std::string& userId,
                      const std::string& deviceId,
                      const DhPublicKey& identity,
                      std::unique_ptr<std::list<PreKeyDataUnique>> newOneTimeKeys,
                      PreKeyDataUnique newSignedKey,
                      KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store);


    };
} // namespace


#endif //LIBCHAT_KEYPROVISIONING_H
