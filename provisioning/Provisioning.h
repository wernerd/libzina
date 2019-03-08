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
#ifndef PROVISIONING_H
#define PROVISIONING_H

/**
 * @file Provisioning.h
 * @brief Interface for the required provisioning server functions
 * @ingroup ZINA
 * @{
 */

#include <string>
#include <list>
#include <utility>

#include "../keymanagment/KeyProvisioningServerApi.h"
#include "../ratchet/crypto/DhPublicKey.h"
#include "../storage/sqlite/SQLiteStoreConv.h"

namespace zina {
    class Provisioning {
    public:
        virtual ~Provisioning() = default;

        /**
         * @brief Remove a ZINA device from user's account.
         *
         * @param scClientDevId the unique device id of one of the user's registered ZINA devices
         * @param authorization authorization data, may be needed for some servers
         * @param result To store the result data of the server, usually in case of an error only
         */
        static int32_t
        removeZinaDevice(const std::string &scClientDevId, const std::string &authorization, std::string *result);

        /**
         * @brief Get the available registered ZINA device of a user
         *
         * A user may register several devices for ZINA usage. A sender (Alice) should send messages to
         * all available devices of the other user (Bob). This keeps Bob's message display on his devices in
         * sync.
         *
         * @param name username of the other user
         * @param authorization authorization data, may be needed for some servers
         * @param deviceIds List of device ids, output
         * @return a list of available device ids (long device ids), @c NULL if the request to server failed.
         */
        static int32_t getZinaDeviceIds(const std::string &name, const std::string &authorization,
                                        std::list<std::pair<std::string, std::string> > &deviceIds);

        static int32_t getUserInfo(const std::string &alias, const std::string &authorization, std::string *result);
    };
} // namespace

/**
 * @}
 */

#endif // PROVISIONING_H
