/*
 * Copyright 2018, Werner Dittmann
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
//
// Created by Werner Dittmann on 11.11.18.
//

#ifndef SZINA_KEYPROVISIONINGSERVERAPI_H
#define SZINA_KEYPROVISIONINGSERVERAPI_H
/**
 * @file
 * @brief Interface definition for key server functions 
 * @ingroup 
 * @{
 * 
 * The ZINA key server should provide some functions to provide key bundle storage and retrieval.
 * 
 * This class provides empty implementations which return a Generic error when called. A key server
 * interface class should inherit this class and provide a implementation. The key management provisioning
 * functions callback to this class to update or retrieve key bundles.
 */

#include <cstdint>
#include <string>
#include "../Constants.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../common/DataStructures.h"

namespace zina {

    class KeyProvisioningServerApi {
    public:

    public:

        /**
         * @brief Update a complete key bundle on the provisioning server.
         *
         * The server specific code takes the data and creates a server specific format, for example JSON or XML,
         * from this data and send it to the server to update the pre-key, signed pre-key and identity key data
         * for a user's device.
         *
         * The server should be able to receive and store the following data:
         * - the user's id and the device id to be able to identify the data
         * - the public part of the long term identity key (never send the private part to the server)
         * - the signed pre key and its signature (if the server supports signed pre-key)
         * - the list of normal, one-time pre-keys
         *
         * @param userId The user's identification, for example unique id, chat address, etc
         * @param deviceId If multi-device feature is supported then this defines the specific device of the user. If the
         *                 feature is not supported the parameter should be an empty string
         * @param identity The user's long term identity key pair
         * @param existingOnetimePreKeys List of one-time pre-keys that already exist, thus before adding the new
         *        one-time pre-keys
         * @param existingSingedPreKeys ordered List of signed pre-key (newest first and after removing excess signed
         *        pre-keys) that already exist, thus before adding the new signed pre-pey
         * @param newOneTimePreKeys The new or updates list of one-time pre-keys, may be nullptr or empty list
         * @param newSignedPreKey The new signed pre-key of the user-id/device-id combination, may be nullptr
         * @return SUCCESS or an error code
         */
        virtual int32_t
        updateKeyBundle(const std::string& userId, const std::string& deviceId,
                        const DhPublicKey& identity,
                        std::unique_ptr<std::list<std::unique_ptr<PreKeyData> > > existingOnetimePreKeys,
                        std::unique_ptr<std::list<std::unique_ptr<PreKeyData> > > existingSingedPreKeys,
                        std::unique_ptr<std::list<std::unique_ptr<PreKeyData> > > newOneTimePreKeys,
                        std::unique_ptr<PreKeyData> newSignedPreKey)
        {
            return GENERIC_ERROR;
        }

        /**
         * @brief Read key bundle data from server, parse it and fill in a key bundle structure.
         *
         * The function gets server specific key bundle data, for example formatted in JSON or XML, parses the data
         * and creates a KeyBundle structure. Usually the server selects an available ont-time pre-time,
         * gets the signed pre-key and the log-term identity key and returns this data to the caller.
         *
         * Depending on the available data the server's KeyBundle contains:
         * - public part of the long term identity key
         * - public part of the selected one-time pre-key
         * - public part of the signed pre-key and its signature
         * - the identifiers of the signed pre-key and the selected pre-key
         *
         * @param userId The user's identification, for example unique id, chat address, etc
         * @param deviceId If multi-device feature is supported then this defines the specific device of the user. If the
         *                 feature is not supported the parameter should be an empty string
         * @return Unique pointer to a KeyBundle data structure, may be a nullptr if not key bundle was available
         */
        virtual KeyBundleUnique
        getKeyBundle(const std::string& userId, const std::string& deviceId)
        {
            return nullptr;
        }
    };
}
/**
 * @}
 */
#endif //SZINA_KEYPROVISIONINGSERVERAPI_H
