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
#include "PreKeys.h"

#include "../ratchet/crypto/EcCurve.h"
#include "../util/b64helper.h"
#include "../util/Utilities.h"

#include <cryptcommon/ZrtpRandom.h>

using namespace std;
using namespace zina;
using json = nlohmann::json;

static unique_ptr<string> preKeyJson(const DhKeyPair &preKeyPair)
{
    LOGGER(INFO, __func__, " -->");
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    json jsn;

    b64Encode(preKeyPair.getPrivateKey().privateData(), preKeyPair.getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["private"] = b64Buffer;

    b64Encode((const uint8_t*)preKeyPair.getPublicKey().serialize().data(), preKeyPair.getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["public"] = b64Buffer;


    LOGGER(DEBUGGING, __func__, " <--");
    return make_unique<string>(jsn.dump());
}

PreKeys::PreKeyData PreKeys::generatePreKey(SQLiteStoreConv* store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    int32_t keyId = 0;
    for (bool ok = false; !ok; ) {
        ZrtpRandom::getRandomData((uint8_t*)&keyId, sizeof(int32_t));
        keyId &= 0x7fffffff;      // always a positive value
        ok = !store->containsPreKey(keyId);
    }
    KeyPairUnique preKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);

    // Create storage format (JSON) of pre-key and store it. Storage encrypts the JSON data
    const auto pk = preKeyJson(*preKeyPair);
    store->storePreKey(keyId, *pk);

    PreKeyData prePair(keyId, move(preKeyPair));

    LOGGER(DEBUGGING, __func__, " <--");
    return prePair;
}

list<PreKeys::PreKeyData>* PreKeys::generatePreKeys(SQLiteStoreConv* store, int32_t num)
{
    LOGGER(DEBUGGING, __func__, " -->");

    auto* pkrList = new std::list<PreKeys::PreKeyData>;

    for (int32_t i = 0; i < num; i++) {
        PreKeys::PreKeyData pkPair = generatePreKey(store);
        pkrList->push_back(move(pkPair));
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return pkrList;
}

KeyPairUnique PreKeys::parsePreKeyData(const string& data) {
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED * 2];   // Twice the max. size on binary data - b64 is times 1.5
    uint8_t binBuffer[MAX_KEY_BYTES_ENCODED];

    json jsn;
    try {
        jsn = json::parse(data);

        if (jsn.find("public") == jsn.end() || jsn.find("private") == jsn.end()) {
            return nullptr;
        }
    } catch (json::exception&) {
        return KeyPairUnique(nullptr);
    }

    string pub = jsn["public"];
    b64Decode(pub.data(), pub.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
    const PublicKeyUnique pubKey = EcCurve::decodePoint(binBuffer);

    // Here we may check the public curve type and do some code to support different curves and
    // create to correct private key. The serialized public key data contains a curve type id. For
    // the time being use Ec255 (DJB's curve 25519).
    string priv = jsn["private"];
    size_t binLength = b64Decode(priv.data(), priv.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
    const PrivateKeyUnique privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

    LOGGER(DEBUGGING, __func__, " <--");
    return KeyPairUnique(new DhKeyPair(*pubKey, *privKey));
}
