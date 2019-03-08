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
#ifndef SCPROVISIONING_H
#define SCPROVISIONING_H

/**
 * @file ScProvisioning.h
 * @brief Implementation of the provisioning interface for Silent Circle provisioning server.
 * @ingroup Zina
 * @{
 */

#include <string>
#include "Provisioning.h"
#include "UserDeviceServerApi.h"

// The fixed strings used in the SC implementation to form the request URLs
// /v1/<user>/axolotl/prekey/<scClientDevId>/?api_key=<API_key> - GET

static const std::string GET("GET");
static const std::string PUT("PUT");
static const std::string DELETE("DELETE");

typedef int32_t (*HTTP_FUNC)(const std::string& requestUri, const std::string& method, const std::string& requestData, std::string* response);

namespace zina {
class ScProvisioning : public Provisioning, public KeyProvisioningServerApi, public UserDeviceServerApi
{
public:

    explicit ScProvisioning(const std::string& authorization) : authorizationCode(authorization) {}

    ~ScProvisioning() override = default;

    // region Key server API implementation
    int32_t
    updateKeyBundle(const std::string& userId, const std::string& deviceId, const DhPublicKey& identity,
                    PreKeysListUnique existingOnetimePreKeys,
                    PreKeysListUnique existingSingedPreKeys,
                    PreKeysListUnique newOneTimePreKeys,
                    PreKeyDataUnique newSignedPreKey) override
    {
        return newPreKeys_V2(deviceId, move(newOneTimePreKeys), nullptr);
    }

    KeyBundleUnique
    getKeyBundle(const std::string& userId, const std::string& deviceId) override;

    int32_t
    getNumberAvailableKeysOnServer(const std::string& userId, const std::string& deviceId) override;

    // endregion

    // region User Device Server API implementation
    int32_t
    prepareDevice(const ZinaConversation& conv,
                  const std::string& deviceId,
                  const std::string& deviceName,
                  KeyProvisioningServerApi& kpsApi,
                  SQLiteStoreConv& store,
                  std::string& resultFromServer) override;

    // endregion

    /**
     * @brief Initialization code must set a HTTP helper function
     * 
     * @param httpHelper Pointer to the helper functions
     */
    static void setHttpHelper(HTTP_FUNC httpHelper);

    ScProvisioning(const ScProvisioning& other)  = delete;
    ScProvisioning& operator=(const ScProvisioning& other)  = delete;
    bool operator==(const ScProvisioning& other) const = delete;

private:

    const std::string authorizationCode;

    friend class Provisioning;
    /**
     * @brief functions pointer to the HTTP helper function
     * 
     * This is a blocking function and returns after the server answered the HTTP request.
     * The @c requestURL does not include the protocol specifier, e.g. HTTP or HTTPS, and 
     * not the domain name. The helper function adds these to form a valid address.
     * 
     * For the SC implementation a request URL looks like this: 
     @verbatim
     /v1/<user>/axolotl/prekey/<scClientDevId>/?api_key=<API_key>
     @endverbatim
     *
     * @param requestUri This is the request URL.
     * @param method the method to use, for example PUT or GET
     * @param requestData This is data for the request, JSON string, not every request has data
     * @param response This string receives the response, usually a JSON formatted string
     * @return the request return code, usually a HTTP code like 200 or something like that.
     */
    static HTTP_FUNC httpHelper_;

    int32_t
    newPreKeys_V2(const std::string &longDevId,
                  PreKeysListUnique newOneTimePreKeys,
                  PreKeyDataUnique newSignedPreKey);


};
} // namespace

/**
 * @}
 */

#endif // SCPROVISIONING_H
