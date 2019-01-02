/*
 * sZina Copyright 2018, Werner Dittmann
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
#include "PreKeys.h"

#include "../ratchet/crypto/EcCurve.h"
#include "../util/Utilities.h"

#include <cryptcommon/ZrtpRandom.h>


using namespace std;
using namespace zina;


static PreKeyDataUnique generateKey(SQLiteStoreConv& store, bool isSigned = false)
{
    int32_t keyId = 0;
    for (bool ok = false; !ok; ) {
        ZrtpRandom::getRandomData((uint8_t*)&keyId, sizeof(int32_t));
        keyId &= 0x7fffffff;      // always a positive value
        if (keyId == 0) {
            continue;
        }
        ok = !store.hasPreKey(keyId);
    }
    auto preKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
    auto preKeyData = make_unique<PreKeyData>(keyId, move(preKeyPair));
    if (!preKeyData->keyPair) {
        preKeyData->result = NO_SUCH_CURVE;
    }
    preKeyData->isSigned = isSigned;
    preKeyData->created = time(nullptr);

   return preKeyData;
}

PreKeyDataUnique
PreKeys::generateOneTime(SQLiteStoreConv& store)
{
    LOGGER(DEBUGGING, __func__, " -->");
    return generateKey(store);
}

int32_t 
PreKeys::generateOneTimeKeys(std::list<PreKeyDataUnique>& keys, SQLiteStoreConv& store, int32_t num)
{
    LOGGER(DEBUGGING, __func__, " -->");
    
    for (int32_t i = 0; i < num; i++) {
        auto pkData = generateOneTime(store);
        if (pkData->result != SUCCESS) {
            return pkData->result;      // bail out in case of error
        }
        keys.push_back(move(pkData));
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}


PreKeyDataUnique
PreKeys::generateSigned(const DhPrivateKey &signingKey, SQLiteStoreConv& store)
{
#ifdef SIGNED_PRE_KEY_SUPPORT
    auto preKeyData = generateKey(store, true);

    uint8_t signature[Ec255PrivateKey::SIGN_LENGTH] = {0};

    // serialize returns the public key as byte data: first byte is the key type,
    // following bytes are the public key bytes
    string encoded = preKeyData->keyPair->getPublicKey().serialize();

    // Sign the encoded public key data
    preKeyData->signature = make_unique<string>();
    int32_t result = EcCurve::calculateSignature(signingKey, reinterpret_cast<const uint8_t*>(encoded.c_str()),
                                                 encoded.size(), signature, Ec255PrivateKey::SIGN_LENGTH);
    if (result != SUCCESS) {
        preKeyData->signature->clear();
        preKeyData->result = result;
        return preKeyData;             // return with an empty signature
    }
    preKeyData->signature->assign(reinterpret_cast<const char*>(signature), Ec255PrivateKey::SIGN_LENGTH);
#else
    PreKeyDataUnique preKeyData;        // an empty pointer
#endif
    return preKeyData;
}

int32_t
PreKeys::verifySigned(const DhPublicKey &verifyingKey, const DhPublicKey &signedKey, const string &signature)
{
#ifdef SIGNED_PRE_KEY_SUPPORT

    // serialize() returns the public key as byte data: first byte is the key type, then the public key data
    string encoded = signedKey.serialize();

    // Now verify
    return EcCurve::verifySignature(verifyingKey,
                                    reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size(),
                                    reinterpret_cast<const uint8_t*>(signature.c_str()), Ec255PrivateKey::SIGN_LENGTH);
#else
    return GENERIC_ERROR;
#endif
}


