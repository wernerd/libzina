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

#include <cstdio>
#include <memory>

#include "ScProvisioning.h"

#include "../util/b64helper.h"
#include "../Constants.h"
#include "../ratchet/crypto/EcCurve.h"
#include "../keymanagment/PreKeys.h"
#include "../util/Utilities.h"

using namespace zina;
using namespace std;
using json = nlohmann::json;


int32_t (*ScProvisioning::httpHelper_)(const std::string&, const std::string&, const std::string&, std::string*) = nullptr;

void ScProvisioning::setHttpHelper(int32_t (*httpHelper)( const std::string&, const std::string&, const std::string&, std::string* ))
{
    httpHelper_ = httpHelper;
}

// **********************************************************************
//
// region Server device handling API

// Implementation of the Provisioning API: Register a device, re-used to set 
// new signed pre-key and to add pre-keys.
// /v1/me/device/<device_id>/axolotl/keys/?api_key=<API_key>
// Method: PUT

static const char* registerRequest = "/v1/me/device/%s/axolotl/keys/?api_key=%s";

int32_t Provisioning::registerZinaDevice(const std::string& request, const std::string& authorization, const std::string& scClientDevId, std::string* result)
{
    LOGGER(DEBUGGING, __func__, " -->");
    char temp[1000];
    snprintf(temp, 990, registerRequest, scClientDevId.c_str(), authorization.c_str());

    std::string requestUri(temp);
    LOGGER(DEBUGGING, __func__, " <--");

    return ScProvisioning::httpHelper_(requestUri, PUT, request, result);
}

// Implementation of the Provisioning API: remove an Axolotl Device 
// /v1/me/device/<device_id>/axolotl/keys/?api_key=<API_key>
// Method: DELETE

int32_t Provisioning::removeZinaDevice(const string& scClientDevId, const string& authorization, std::string* result)
{
    LOGGER(DEBUGGING, __func__, " -->");
    char temp[1000];
    snprintf(temp, 990, registerRequest, scClientDevId.c_str(), authorization.c_str());
    std::string requestUri(temp);
    LOGGER(DEBUGGING, __func__, " <--");

    return ScProvisioning::httpHelper_(requestUri, DELETE, Empty, result);

}

// Implementation of the Provisioning API: Get Available Axolotl registered devices of a user
// Request URL: /v1/user/wernerd/devices/?filter=axolotl&api_key=<apikey>
// Method: GET
/*
 {
    "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
    {"devices": [{"version": 1, "id": <string>, "device_name": <string>}]}  # array of known Axolotl ScClientDevIds for this user/account
 }
 */
static const char* getUserDevicesRequest = "/v1/user/%s/device/?filter=axolotl&api_key=%s";

int32_t Provisioning::getZinaDeviceIds(const std::string& name, const std::string& authorization, list<pair<string, string> > &deviceIds)
{
    LOGGER(DEBUGGING, __func__, " -->");

    if (ScProvisioning::httpHelper_ == nullptr) {
        LOGGER(ERROR, __func__,  "ZINA library not correctly initialized");
        return 500;
    }

    string encoded = Utilities::urlEncode(name);

    char temp[1000];
    snprintf(temp, 990, getUserDevicesRequest, encoded.c_str(), authorization.c_str());

    std::string requestUri(temp);

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, &response);

    if (code >= 400) {
        return NETWORK_ERROR;
    }
    if (response.empty()) {
        return NO_DEVS_FOUND;
    }

    try {
        json jsn = json::parse(response);

        json devIds = jsn.at("devices");
        if (!devIds.is_array()) {
            LOGGER(ERROR, __func__,  "No devices array in response, ignoring.");
            return NO_DEVS_FOUND;
        }

        for (auto& item : devIds) {
            string id = item.value("id", "");
            if (id.empty()) {
                LOGGER(ERROR, __func__,  "Missing device id, ignoring.");
                continue;
            }
            string nameString = item.value("device_name", "");
            pair<string, string> idName(id, nameString);
            deviceIds.push_back(idName);
        }
    } catch (json::exception& e) {
        LOGGER(ERROR, __func__,  "Wrong device response JSON data, ignoring: ", response);
        return NETWORK_ERROR;
    }

    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}

// endregion

// **********************************************************************
//
// region Server key handling API

// Implementation of the Provisioning API: Set new pre-keys
// /v1/me/device/<device_id>/axolotl/keys/?api_key=<API_key>
// Method: PUT
/*
 {
    "prekeys" : [{
        "id" :        <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    },
....
    {
        "id" :        <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    }]
 }
*/

int32_t
ScProvisioning::newPreKeys_V2(const std::string &longDevId, PreKeysListUnique newOneTimePreKeys, PreKeyDataUnique newSignedPreKey)
{
    LOGGER(DEBUGGING, __func__, " -->");

    char temp[1000];
    snprintf(temp, 990, registerRequest, longDevId.c_str(), authorizationCode.c_str());
    std::string requestUri(temp);

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    json jsn;

    json jsonPkrArray = json::array();

    for (const auto& preKey : *newOneTimePreKeys) {
        json pkrObject;
        pkrObject["id"] = preKey->keyId;

        // Get pre-key's public key data, serialized
        const std::string data = preKey->keyPair->getPublicKey().serialize();

        b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        pkrObject["key"] = b64Buffer;
        jsonPkrArray += pkrObject;
    }
    jsn["prekeys"] = jsonPkrArray;

    LOGGER(DEBUGGING, __func__, " <--");

    string result;
    return ScProvisioning::httpHelper_(requestUri, PUT, jsn.dump(), &result);
}

// Implementation of the Provisioning API: Get Pre-Key
// Request URL: /v1/user/<user>/device/<devid>/?api_key=<apikey>
// Method: GET
/*
 * Server response:
{
  "axolotl": {
     "preKey": {
         "id": 740820098, 
         "key": "AbInUu24ot/07lc4q432zrwd+xbZA8oS1+OB/8j1CKU3"
     },
     "identity_key": "AR2/g2VTSYpqbnRJVi4Wdz8hAnZZmHvknf15qRrClZcs"
  }
}
*/
static const char* getPreKeyRequest = "/v1/user/%s/device/%s/?api_key=%s";

KeyBundleUnique ScProvisioning::getKeyBundle(const std::string& userId, const std::string& deviceId)
{
    LOGGER(DEBUGGING, __func__, " -->");

    string encoded = Utilities::urlEncode(userId);

    char temp[1000];
    snprintf(temp, 990, getPreKeyRequest, encoded.c_str(), deviceId.c_str(), authorizationCode.c_str());
    std::string requestUri(temp);

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, &response);

    if (code >= 400)
        return nullptr;

    uint8_t pubKeyBuffer[MAX_KEY_BYTES_ENCODED];

    try {
        auto keyBundle = make_unique<KeyBundle>();
        auto j = json::parse(response);

        auto axoData = j.at("axolotl");     // at() throws if element not found, use value(..., ...) to use default, not throw

        string identity = axoData.at("identity_key");
        b64Decode(identity.data(), identity.size(), pubKeyBuffer, MAX_KEY_BYTES_ENCODED);
        keyBundle->identityKey = EcCurve::decodePoint(pubKeyBuffer);

        auto preKey = axoData.at("preKey");
        keyBundle->preKeyId = preKey.at("id");

        string pkyPub = preKey.at("key");
        b64Decode(pkyPub.data(), pkyPub.size(), pubKeyBuffer, MAX_KEY_BYTES_ENCODED);
        keyBundle->preKey = EcCurve::decodePoint(pubKeyBuffer);
        return keyBundle;

    } catch (json::exception& e) {
        LOGGER(ERROR, "Wrong pre-key bundle JSON data, ignoring: ", e.what());
        return nullptr;
    }
}

// Implementation of the Provisioning API: Available pre-keys
// Request URL: /v1/me/device/<device_id>/"
// Method: GET
/*
 * Server response:
 {
  "silent_text": {
      "username": "xxx@xmpp-dev.silentcircle.net", 
      "password": "badcafe"
     },
  "silent_phone": {
      "username": "xxx", 
      "tns": {
          "+15555555555": {
              "oca_region": "US", "oca_area": "New York", "provider": "Test"
          }
       }, 
       "current_modifier": 0, 
       "services": {
           "global": {
               "minutes_left": 100, "min_tier": 100
           }
       },
       "numbers": [{"region": "US", "number": "+15555555555", "area": "New York"}], 
       "owner": "sc", 
       "password": "topsecret", 
       "tls1": "server1.silentcircle.net", "tls2": "server2.silentcircle.net"
   }, 
   "axolotl": {
       "version": 1, 
       "prekeys": [
           {"id": 4711, "key": "badcafebeafdead"}, 
           {"id": 815, "key":  "cafecafebadbad"}, 
        ], 
        "identity_key": "deadbeaf"
   }, 
   "push_tokens": []}
 */
static const char* getNumberPreKeys = "/v1/me/device/%s/?api_key=%s";

int32_t
ScProvisioning::getNumberAvailableKeysOnServer(const std::string& userId, const std::string& deviceId)
{
    LOGGER(DEBUGGING, __func__, " -->");

    char temp[1000];
    snprintf(temp, 990, getNumberPreKeys, deviceId.c_str(), authorizationCode.c_str());

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(temp, GET, Empty, &response);

    if (code >= 400 || response.empty())
        return -1;

    int32_t numIds;
    json jsn;
    try {
        jsn = json::parse(response);

        json keyIds = jsn.at("axolotl").at("prekeys");
        if (!keyIds.is_array()) {
            LOGGER(ERROR, "No pre-keys array, ignoring.");
            return -1;
        }
        numIds = static_cast<int32_t>(keyIds.size());
    } catch (json::exception& e) {
        LOGGER(ERROR, "Wrong pre-key bundle JSON data, ignoring.");
        return -1;
    }

    LOGGER(DEBUGGING, __func__, " <--");
    return numIds;
}

// endregion

// **********************************************************************
//
// region User Info  API

// Implementation of the Provisioning API: Get available user info from provisioning server
// Request URL: /v1/user/<name>/?api_key=<apikey>
// Method: GET
static const char* getUserInfoRequest = "/v1/user/%s/?api_key=%s";

int32_t Provisioning::getUserInfo(const string& alias,  const string& authorization, string* result)
{
    LOGGER(DEBUGGING, __func__, " -->");

    string encoded = Utilities::urlEncode(alias);
    char temp[1000];
    snprintf(temp, 990, getUserInfoRequest, encoded.c_str(), authorization.c_str());
    string requestUri(temp);

    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, result);

    LOGGER(DEBUGGING, __func__, " <--");
    return code;
}

// endregion

