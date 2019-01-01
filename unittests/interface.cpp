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

#include "../storage/sqlite/SQLiteStoreConv.h"

#include "../ratchet/crypto/Ec255PrivateKey.h"
#include "../ratchet/crypto/Ec255PublicKey.h"
#include "../ratchet/crypto/EcCurve.h"
#include "../ratchet/state/ZinaConversation.h"

#include "../interfaceApp/AppInterfaceImpl.h"
#include "../util/b64helper.h"
#include "../keymanagment/PreKeys.h"
#include "../provisioning/ScProvisioning.h"

#include "gtest/gtest.h"

using namespace std;

static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};
static const uint8_t keyInData_1[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,32};
static const uint8_t keyInData_2[] = {"ZZZZZzzzzzYYYYYyyyyyXXXXXxxxxxW"};  // 32 bytes
static     std::string empty;

using namespace zina;
using namespace std;
using json = nlohmann::json;

SQLiteStoreConv* store;

static const std::string bob("bob");
static const std::string bobDevId("bobsidentifier");
static const std::string bobAuth("bobsauthorization");
static const int32_t bobRegisterId = 4711;

static const Ec255PublicKey bobIdpublicKey(keyInData);

static unique_ptr<PreKeyData> bobPreKey;

// This simulates an answer from the provisioning server repsoning to register a device
// If necessary check for correctness of request data
//
static int32_t helper0(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
//     cerr << method << " " << requestUrl << '\n';
//     cerr << data;
    return 200;
}

TEST(RegisterRequest, Basic)
{
    LOGGER_INSTANCE setLogLevel(ERROR);

    // Open the store with some key
    store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
    }
    ScProvisioning::setHttpHelper(helper0);

    string name("wernerd");
    string devId("myDev-id");
    AppInterfaceImpl uiIf(store, name, string("myAPI-key"), devId);
    auto ownAxoConv = ZinaConversation::loadLocalConversation(name, *store);

    if (!ownAxoConv->isValid()) {  // no yet available, create one. An own conversation has the same local and remote name
        KeyPairUnique idKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
        ownAxoConv->setDHIs(move(idKeyPair));
        ownAxoConv->storeConversation(*store);
    }

    std::string result;
    int32_t ret = uiIf.registerZinaDevice(&result);

    ASSERT_TRUE(ret > 0) << "Actual return value: " << ret;
}


// This simulates an answer from the provisioning server repsoning to a get pre key request
//
//  {"axolotl": {
//      "prekey": {"id": 560544384, "key": "AcmSyjsgM6q7dhD1qMAp4chKYJEK3U/B6XYSfdrefsr"},
//      "identity_key": "AUIXDEamRULpGsdG1spm9uFdSgi2V+iUjhszedfhsafjd"
//      }
//  }
static int32_t helper1(const std::string& requestUrl, const std::string& method, const std::string& reqData, std::string* response)
{

//    cerr << method << " " << requestUrl << '\n';

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5


    json jsn;

    json  axolotl;

    std::string data = bobIdpublicKey.serialize();
    size_t b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    axolotl["identity_key"] = b64Buffer;

    // Need a key pair here
    const Ec255PublicKey baseKey_1(keyInData_1);
    const Ec255PrivateKey basePriv_1(keyInData_2);

    bobPreKey = make_unique<PreKeyData>(33, make_unique<DhKeyPair>(baseKey_1, basePriv_1));

    json jsonPkr;
    jsonPkr["id"]= bobPreKey->keyId;

    // Get pre-key's public key data, serialized and add it to JSON
    data = bobPreKey->keyPair->getPublicKey().serialize();
    b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsonPkr["key"] = b64Buffer;
    axolotl["preKey"] = jsonPkr;
    jsn["axolotl"] = axolotl;

    response->append(jsn.dump());
//    cerr << *response;
    return 200;
}

TEST(PreKeyBundle, Basic)
{
    LOGGER_INSTANCE setLogLevel(ERROR);

//    store = SQLiteStoreConv::getStore();
//    if (!store->isReady()) {
//        store->setKey(std::string((const char*)keyInData, 32));
//        store->openStore(std::string());
//    }
    ScProvisioning::setHttpHelper(helper1);

    auto keyBundle = Provisioning::getPreKeyBundle(bob, bobDevId, bobAuth);
    
    ASSERT_EQ(bobPreKey->keyId, keyBundle->preKeyId);
    ASSERT_TRUE(bobIdpublicKey == *static_cast<const Ec255PublicKey*>(keyBundle->identityKey.get()));
}

// This simulates an answer from the provisioning server repsonding number of availabe pre-keys
//
/*
 {
    "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
    "scClientDevId"  : <string>,         # the same string as used to register the device (v1/me/device/{device_id}/)
    "registrationId" : <int32_t>,        # the client's Axolotl registration id
    "availablePreKeys" : <int32_t>       # number of available pre-keys on the server
 }
 */

static int32_t helper2(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
//   std::cerr << method << " " << requestUrl << '\n';

    json jsn;
    jsn["version"] = 1;
    jsn["scClientDevId"] = bobDevId;
    jsn["registrationId"] = bobRegisterId;
    jsn["availablePreKeys"] = 10;

    response->append(jsn.dump());

//    std::cerr << *response;
    return 200;
}

// TEST(AvailabePreKeys, Basic)
// {
//     store = SQLiteStoreConv::getStore();
//     if (!store->isReady()) {
//         store->setKey(std::string((const char*)keyInData, 32));
//         store->openStore(std::string());
//     }
//     ScProvisioning::setHttpHelper(helper2);
// 
//     ASSERT_EQ(10, Provisioning::getNumPreKeys(bobDevId, bobAuth));
// }


// This simulates an answer from the provisioning server responding a user's available Axolotl devices
//
/*
 * Returns the device ids.
 * {
   "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
   {"devices": ["id": <string>, "device_name": <string>}]}  # array of known Axolotl ScClientDevIds for this user/account
   }
 */

static int32_t helper3(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
//     std::cerr << method << " " << requestUrl << '\n';

    json jsn = { {"version", 1} };

    json devArray = json::array();
    devArray += json {
            {"id", "longDevId_1"}, {"device_name", "Device_1"}
    };
    devArray += json {
            {"id", "longDevId_2"}, {"device_name", "Device_2"}
    };
    devArray += json {
            {"id", "longDevId_3"}, {"device_name", "Device_3"}
    };
    jsn["devices"] = devArray;

    response->append(jsn.dump());
//    std::cerr << *response;c
    return 200;
}

TEST(GetDeviceIds, Basic)
{
    LOGGER_INSTANCE setLogLevel(ERROR);

    store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
    }
    ScProvisioning::setHttpHelper(helper3);

    list<pair<string, string> > devIds;
    int32_t errorCode = Provisioning::getZinaDeviceIds(bob, bobAuth, devIds);

    ASSERT_EQ(SUCCESS, errorCode);

    ASSERT_EQ(3, devIds.size());
    string id = devIds.front().first;
    devIds.pop_front();
    string id1("longDevId_1");
    ASSERT_EQ(id1, id);

    id = devIds.front().first;
    devIds.pop_front();
    std::string id2("longDevId_2");
    ASSERT_EQ(id2, id);

    id = devIds.front().first;
    devIds.pop_front();
    std::string id3("longDevId_3");
    ASSERT_EQ(id3, id);
}

// This simulates an answer from the provisioning server responding to set a new signed pre-key
// If necessary check for correctness of request data
//
static int32_t helper4(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
//     std::cerr << method << " " << requestUrl << '\n';
//     std::cerr << data;

    return 200;
}


// This simulates an answer from the provisioning server responding to add new prekeys
// If necessary check for correctness of request data
//
static int32_t helper5(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
//     std::cerr << method << " " << requestUrl << '\n';
//     std::cerr << data;

    return 200;
}

TEST(newPreKeys, Basic)
{
    LOGGER_INSTANCE setLogLevel(ERROR);

    store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
    }
    ScProvisioning::setHttpHelper(helper5);

    std::string result;
    int32_t ret = Provisioning::newPreKeys(store, bobDevId, bobAuth, 10, &result);
    ASSERT_TRUE(ret > 0) << "Actual return value: " << ret;
}
