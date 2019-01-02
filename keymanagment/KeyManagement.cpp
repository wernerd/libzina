//
// Created by wdi on 21.06.18.
//

#include "KeyManagement.h"

#include "../ratchet/crypto/EcCurve.h"
#include "../Constants.h"
#include "../util/Utilities.h"
#include "../util/b64helper.h"
#include "PreKeys.h"

using namespace std;
using namespace zina;
using json = nlohmann::json;

static void removeOldSignedKeys(list<unique_ptr<PreKeyData> >& preKeys, SQLiteStoreConv& store)
{
    if (preKeys.size() > 3) {
        auto remove = move(preKeys.back());
        store.removePreKey(remove->keyId);
        preKeys.pop_back();
    }
}


static StringUnique
preKeyDataToJson(const PreKeyData &preKeyData)
{
    LOGGER(INFO, __func__, " -->");
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    json j;

    auto& preKeyPair = *preKeyData.keyPair;

    b64Encode(preKeyPair.getPrivateKey().privateData(), preKeyPair.getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    j["private"] = b64Buffer;

    b64Encode((const uint8_t*)preKeyPair.getPublicKey().serialize().data(), preKeyPair.getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    j["public"] = b64Buffer;

    j["isSigned"] = preKeyData.isSigned;
    j["created"] = preKeyData.created;
    j["keyid"] = preKeyData.keyId;

    if (preKeyData.isSigned) {
        b64Encode((const uint8_t*)preKeyData.signature->data(), preKeyData.signature->size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        j["signature"] = b64Buffer;
    }

    LOGGER(DEBUGGING, __func__, " <--");
    return make_unique<string>(j.dump());
}

static void
jsonToPreKeyData(const string &data, PreKeyData &preKeyData)
{
    uint8_t binBuffer[MAX_KEY_BYTES_ENCODED];

    try {
        auto j = json::parse(data);

        auto pub = j.value("public", "");
        auto priv = j.value("private", "");

        if (pub.empty() || priv.empty()) {
            preKeyData.result = NO_PRE_KEY_FOUND;
            return;
        }

        b64Decode(pub.data(), pub.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        const PublicKeyUnique pubKey = EcCurve::decodePoint(binBuffer);

        // Here we may check the public curve type and do some code to support different curves and
        // create to correct private key. The serialized public key data contains a curve type id. For
        // the time being use Ec255 (DJB's curve 25519).
        size_t binLength = b64Decode(priv.data(), priv.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        const PrivateKeyUnique privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

        auto pair = make_unique<const DhKeyPair>(*pubKey, *privKey);
        preKeyData.keyPair = make_unique<const DhKeyPair>(*pubKey, *privKey);

        preKeyData.isSigned = j.value("isSigned", false);
        preKeyData.created = llround(j.value("created", 0));

        if (preKeyData.isSigned) {
            auto sig = j.value("signature", "");
            binLength = b64Decode(sig.data(), sig.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            preKeyData.signature = make_unique<string>();
            preKeyData.signature->assign(reinterpret_cast<const char*>(binBuffer), binLength);
        }
        LOGGER(DEBUGGING, __func__, " <--");
        return;

    } catch (json::parse_error& e) {
        preKeyData.result = NO_PRE_KEY_FOUND;
        return;
    }
}

static int32_t
fillKeyList(bool isSigned, list<PreKeyDataUnique>& keyList, SQLiteStoreConv& store)
{
    map<int32_t, string> fromDb;

    auto result = isSigned ? store.loadAllSignedPreKeys(fromDb) : store.loadAllOneTimePreKeys(fromDb);
    if (SQL_FAIL(result)) {
        return DATABASE_ERROR;
    }
    for (const auto& entry : fromDb) {
        auto preKeyData = make_unique<PreKeyData>(entry.first, nullptr);
        jsonToPreKeyData(entry.second, *preKeyData);
        if (preKeyData->result != SUCCESS) {
            continue;
        }
        keyList.push_back(move(preKeyData));
    }
    return SUCCESS;
}


int32_t
KeyManagement::createInitialSet(const std::string& userId,
                                  const string& deviceId,
                                  const DhKeyPair& identity,
                                  KeyProvisioningServerApi& serverApi,
                                  SQLiteStoreConv& store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    auto signedKey = PreKeys::generateSigned(identity.getPrivateKey(), store);
    if (signedKey->result != SUCCESS) {
        return signedKey->result;
    }

    auto oneTimeKeys = make_unique<std::list<PreKeyDataUnique>>();
    auto status = PreKeys::generateOneTimeKeys(*oneTimeKeys, store);
    if (status != SUCCESS) {
        return status;
    }
    LOGGER(DEBUGGING, __func__, " <--");

    return updatePreKeys(userId, deviceId, identity.getPublicKey(), move(oneTimeKeys), move(signedKey), serverApi, store);
}

int32_t
KeyManagement::addNewPreKeys(int32_t num,
                               const std::string& userId,
                               const std::string& deviceId,
                               const DhPublicKey& identity,
                               KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store)
{
    LOGGER(DEBUGGING, __func__, " -->");
    auto oneTimeKeys = make_unique<std::list<PreKeyDataUnique>>();
    auto status = PreKeys::generateOneTimeKeys(*oneTimeKeys, store, num);
    if (status != SUCCESS) {
        return status;
    }

    LOGGER(DEBUGGING, __func__, " <--");
    return updatePreKeys(userId, deviceId, identity, move(oneTimeKeys), nullptr, serverApi, store);;
}

int32_t
KeyManagement::addSignedPreKey(const std::string& userId, const std::string& deviceId,
                                 const DhKeyPair& identity,
                                 KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store)
{
    LOGGER(DEBUGGING, __func__, " -->");
    // generates a signed pre-key in DB
    auto signedKey = PreKeys::generateSigned(identity.getPrivateKey(), store);
    if (signedKey->result != SUCCESS) {
        return signedKey->result;
    }
    LOGGER(DEBUGGING, __func__, " <--");

    return updatePreKeys(userId, deviceId, identity.getPublicKey(), nullptr, move(signedKey), serverApi, store);
}


int32_t
KeyManagement::updatePreKeys(const std::string& userId, const std::string& deviceId,
                               const DhPublicKey& identity,
                               unique_ptr<std::list<PreKeyDataUnique>> newOneTimeKeys,
                               PreKeyDataUnique newSignedKey,
                               KeyProvisioningServerApi& serverApi, SQLiteStoreConv& store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    // Get existing data before updating with the one keys
    auto existingOneTimeKeys = make_unique<std::list<PreKeyDataUnique>>();
    getAllOneTimeFromDb(*existingOneTimeKeys, store);

    auto existingSignedKeys = make_unique<std::list<PreKeyDataUnique>>();
    getAllSignedFromDb(*existingSignedKeys, store);

    if (newOneTimeKeys) {
        for (const auto& oneTimeKey : *newOneTimeKeys) {
            const auto pk = preKeyDataToJson(*oneTimeKey);
            auto result = store.storePreKey(oneTimeKey->keyId, *pk);
            if (SQL_FAIL(result)) {
                return DATABASE_ERROR;
            }
        }
    }
    if (newSignedKey) {
        const auto pk = preKeyDataToJson(*newSignedKey);
        auto result = store.storePreKey(newSignedKey->keyId, *pk, true);
        if (SQL_FAIL(result)) {
            return DATABASE_ERROR;
        }

    }
    auto result = serverApi.updateKeyBundle(userId, deviceId, identity,
            move(existingOneTimeKeys), move(existingSignedKeys),
            move(newOneTimeKeys), move(newSignedKey));
    LOGGER(DEBUGGING, __func__, " <--, result: ", result);

    return result;
}

PreKeyDataUnique
KeyManagement::getOneTimeFromDb(int32_t keyId, SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    auto preKeyData = make_unique<PreKeyData>(keyId, nullptr);

    string data;
    auto result = store.loadPreKey(keyId, data);
    if (SQL_FAIL(result) || data.empty()) {
        preKeyData->result = NO_PRE_KEY_FOUND;
        return preKeyData;
    }
    jsonToPreKeyData(data, *preKeyData);
    Utilities::wipeString(data);

    LOGGER(DEBUGGING, __func__, " <--");
    return preKeyData;
}

int32_t
KeyManagement::removeOneTimeFromDb(int32_t keyId, SQLiteStoreConv &store)
{
    auto result = store.removePreKey(keyId);
    if (SQL_FAIL(result)) {
        return DATABASE_ERROR;
    }
    return SUCCESS;
}

int32_t
KeyManagement::getAllOneTimeFromDb(list<PreKeyDataUnique>& keyList, SQLiteStoreConv& store)
{
    return fillKeyList(false, keyList, store);
}

int32_t
KeyManagement::getAllSignedFromDb(list<PreKeyDataUnique>& keyList, SQLiteStoreConv& store)
{
    auto retValue =  fillKeyList(true, keyList, store);
    auto timeCmp = [](unique_ptr<PreKeyData>& first, unique_ptr<PreKeyData>& second) {
        return first->created > second->created;
    };

    // newest signed pre-key to top
    keyList.sort(timeCmp);

    removeOldSignedKeys(keyList, store);
    return retValue;
}
