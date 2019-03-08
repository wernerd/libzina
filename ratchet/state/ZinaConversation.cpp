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
#include <limits.h>
#include "ZinaConversation.h"
#include "../../util/b64helper.h"
#include "../crypto/EcCurve.h"
#include "../../util/Utilities.h"

using namespace zina;
using namespace std;
using json = nlohmann::json;

unique_ptr<ZinaConversation>
ZinaConversation::loadConversation(const string& localUser, const string& user, const string& deviceId, SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");
    int32_t result;

    // Create new conversation object
    auto conv = make_unique<ZinaConversation>(localUser, user, deviceId);
    conv->setErrorCode(SUCCESS);

    bool found = store.hasConversation(user, deviceId, localUser, &result);
    if (SQL_FAIL(result)) {
        conv->errorCode_ = DATABASE_ERROR;
        conv->sqlErrorCode_ = result;
        return conv;
    }
    if (!found) {
        LOGGER(INFO, __func__, " <-- No such conversation, return empty conversation: ", user, ", device: ", deviceId);
        return conv;            // SUCCESS, however return an empty conversation
    }

    StringUnique data = store.loadConversation(user, deviceId, localUser, &result);
    if (SQL_FAIL(result)) {
        conv->errorCode_ = DATABASE_ERROR;
        return conv;
    }
    if (!data || data->empty()) {   // Illegal state, should not happen
        LOGGER(ERROR, __func__, " <-- Cannot load conversation data: ", user, ", ", deviceId);
        conv->errorCode_ = NO_SESSION_DATA;
        return conv;
    }

    conv->deserialize(*data);
    conv->valid_ = true;
    LOGGER(DEBUGGING, __func__, " <--");
    return conv;
}

int32_t ZinaConversation::storeConversation(SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    const string* data = serialize();

    int32_t result= store.storeConversation(partner_.getName(), deviceId_, localUser_, *data);
    Utilities::wipeMemory((void*)data->data(), data->size());

    delete data;
    if (SQL_FAIL(result)) {
        errorCode_ = DATABASE_ERROR;
        sqlErrorCode_ = result;
        LOGGER(ERROR, __func__, " <--, error: ");
        return result;
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}

// Currently not used, maybe we need to re-enable it, depending on new user UID (canonical name) design
#if 0
int32_t ZinaConversation::renameConversation(const string& localUserOld, const string& localUserNew,
                                            const string& userOld, const string& userNew, const string& deviceId)
{
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    if (!store->hasConversation(userOld, deviceId, localUserOld)) {
        return SQLITE_ERROR;
    }

    string* data = store->loadConversation(userOld, deviceId, localUserOld);
    if (data == NULL || data->empty()) {   // Illegal state, should not happen
        return SQLITE_ERROR;
    }

    // Create conversation object with the new names. Then deserialize() the old data
    // into the new object. This does not overwrite the new names set in the 
    // ZinaConversation object.
    ZinaConversation*  conv = new ZinaConversation(localUserNew, userNew, deviceId);
    conv->deserialize(*data);
    delete data;

    // Store the conversation with new name and the old data, only name and partner
    // are changed in the data object.
    conv->storeConversation();
    delete conv;

    // Now remove the old conversation
    int32_t sqlCode;
    store->deleteConversation(userOld, deviceId, localUserOld, &sqlCode);
    return sqlCode;
}
#endif

int32_t ZinaConversation::storeStagedMks(SQLiteStoreConv &store) {
    LOGGER(DEBUGGING, __func__, " -->");

    for (; !stagedMk.empty(); stagedMk.pop_front()) {
        string& mkIvMac = stagedMk.front();
        if (!mkIvMac.empty()) {
            int32_t result = store.insertStagedMk(partner_.getName(), deviceId_, localUser_, mkIvMac);
            if (SQL_FAIL(result)) {
                errorCode_ = DATABASE_ERROR;
                sqlErrorCode_ = result;
                LOGGER(ERROR, __func__, " <--, error: ", result);
                return result;
            }
            Utilities::wipeString(mkIvMac);
        }
    }
    clearStagedMks(stagedMk, store);
    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}

void ZinaConversation::clearStagedMks(list<string> &keys, SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    for (; !keys.empty(); keys.pop_front()) {
        string& mkIvMac = keys.front();
        // This actually clears the memory of the string inside the list
        Utilities::wipeString(mkIvMac);
    }

    // Cleanup old MKs, no harm if this DB function fails due to DB problems
    time_t timestamp = time(0) - MK_STORE_TIME;
    store.deleteStagedMk(timestamp);
    LOGGER(DEBUGGING, __func__, " <--");
}

int32_t ZinaConversation::loadStagedMks(list<string> &keys, SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    int32_t result = store.loadStagedMks(partner_.getName(), deviceId_, localUser_, keys);

    if (SQL_FAIL(result)) {
        return DATABASE_ERROR;
    }
    LOGGER(INFO, __func__, " Number of loaded pre-keys: ", keys.size());
    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}

void ZinaConversation::deleteStagedMk(string& mkiv, SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");
    store.deleteStagedMk(partner_.getName(), deviceId_, localUser_, mkiv);
    LOGGER(DEBUGGING, __func__, " <--");
}

string ZinaConversation::lookupSecondaryDevId(int32_t prekeyId)
{
    for (auto& secInfo : secondaryRatchets) {
        if (secInfo->preKeyId == prekeyId) {
            return secInfo->deviceId;
        }
    }
    return Empty;
}

void ZinaConversation::saveSecondaryAddress(const std::string& secondaryDevId, int32_t preKeyId)
{
    unique_ptr<SecondaryInfo> secInfo(new SecondaryInfo);

    secInfo->deviceId = secondaryDevId;
    secInfo->preKeyId = preKeyId;
    secInfo->creationTime = time(nullptr);

    secondaryRatchets.push_back(move(secInfo));
}

unique_ptr<ZinaConversation>
ZinaConversation::getSecondaryRatchet(int32_t index, SQLiteStoreConv &store)
{
    if (index < 0 || index >= secondaryRatchets.size()) {
        return unique_ptr<ZinaConversation>();
    }
    auto conv = loadConversation(getLocalUser(), getPartner().getName(), secondaryRatchets[index]->deviceId, store);

    if (!conv->isValid()) {
        return unique_ptr<ZinaConversation>();
    }
    return conv;
}

void ZinaConversation::deleteSecondaryRatchets(SQLiteStoreConv &store)
{
    for (auto& secInfo : secondaryRatchets) {
        store.deleteConversation(getPartner().getName(), secInfo->deviceId, getLocalUser());
    }

}
/* *****************************************************************************
 * Private functions
 ***************************************************************************** */

// No need to parse name, localName, partner name and device id. Already set
// with constructor.
void ZinaConversation::deserialize(const std::string& data)
{
    LOGGER(DEBUGGING, __func__, " -->");

    json jsn = json::parse(data);

    partner_.setAlias(jsn["partner"]["alias"]);
    deviceName_ = jsn.value("deviceName", "");

    uint8_t binBuffer[MAX_KEY_BYTES_ENCODED];       // max. size on binary data

    size_t binLength;

    // Get RK b64 string, decode and store
    auto b64data = jsn.value("RK", "");
    if (!b64data.empty()) {
        binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        RK.assign(reinterpret_cast<const char*>(binBuffer), binLength);
    }

    // Get the DHRs key pair
    auto keyObject = jsn.find("DHRs");
    if (keyObject != jsn.end()) {
        b64data = (*keyObject).value("public", "");
        if (!b64data.empty()) {
            b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PublicKeyUnique pubKey = EcCurve::decodePoint(binBuffer);

            // Here we may check the public curve type and do some code to support different curves and
            // create to correct private key. The serialized public key data contain a curve type id. For
            // the time being use Ec255 (DJB's curve 25519).
            b64data = (*keyObject).value("private", "");
            binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PrivateKeyUnique privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

            DHRs = KeyPairUnique(new DhKeyPair(*pubKey, *privKey));
        }
    }

    b64data = jsn.value("DHRr", "");
    if (!b64data.empty()) {
        b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        DHRr = EcCurve::decodePoint(binBuffer);
    }

    // Get the DHIs key pair
    keyObject = jsn.find("DHIs");
    if (keyObject != jsn.end()) {
        b64data = (*keyObject).value("public", "");
        if (!b64data.empty()) {
            b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PublicKeyUnique pubKey = EcCurve::decodePoint(binBuffer);

            b64data = (*keyObject).value("private", "");
            binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PrivateKeyUnique privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

            DHIs = KeyPairUnique(new DhKeyPair(*pubKey, *privKey));
        }
    }

    b64data = jsn.value("DHIr", "");
    if (!b64data.empty()) {
        b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        DHIr = EcCurve::decodePoint(binBuffer);
    }

    // Get the A0 key pair
    keyObject = jsn.find("A0");
    if (keyObject != jsn.end()) {
        b64data = (*keyObject).at("public");
        if (!b64data.empty()) {
            b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PublicKeyUnique pubKey = EcCurve::decodePoint(binBuffer);

            b64data = (*keyObject).value("private", "");
            binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
            const PrivateKeyUnique privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

            A0 = KeyPairUnique(new DhKeyPair(*pubKey, *privKey));
        }
    }

    // Get CKs b64 string, decode and store
    b64data = jsn.value("CKs", "");
    if (!b64data.empty()) {
        binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        CKs.assign((const char*)binBuffer, binLength);
    }

    // Get CKr b64 string, decode and store
    b64data = jsn.value("CKr", "");
    if (!b64data.empty()) {
        binLength = b64Decode(b64data.data(), b64data.size(), binBuffer, MAX_KEY_BYTES_ENCODED);
        CKr.assign((const char*)binBuffer, binLength);
    }

    Ns = jsn["Ns"];
    Nr = jsn["Nr"];
    PNs = jsn["PNs"];
    preKeyId = jsn["preKeyId"];
    ratchetFlag = jsn["ratchet"] != 0;

    if (jsn.find("zrtpState") != jsn.end()) {
        zrtpVerifyState = jsn["zrtpState"];
    }
    {
        uint32_t ctxid = jsn.value("contextId", 0);
        if (ctxid == INT_MAX) {
            LOGGER(WARNING, __func__, " <-- ZINA contextId is clamped value; undecryptable messages possible");
        }
        if (ctxid < 0) {
            LOGGER(WARNING, __func__, " <-- ZINA contextId is less than zero; this is unexpected");
        }
        contextId = ctxid;
    }
        if (jsn.find("contextId2") != jsn.end()) {
        contextId2 = jsn.value("contextId2", 0);
        hasContextId2 = true;
    }
    // We have to check that the `contextId` is not zero because this
    // function is called on a very empty object representing our own
    // device; verifing the `contextId` is nonzero excludes this
    // pseudo-peer.
    if (contextId != 0 && !hasContextId2) {
        LOGGER(WARNING, __func__, " <-- Supporting ZINA conversation without contextId2");
    }
    versionNumber = jsn["versionNumber"];
    identityKeyChanged = jsn["identityKeyChanged"];
    if (zrtpVerifyState > 0) {
        identityKeyChanged = false;
    }
        auto secondaries = jsn.find("secondaries");
        if (secondaries != jsn.end()) {
            for (auto& arrayItem : secondaries->items()) {
                auto secInfo = make_unique<SecondaryInfo>();
                secInfo->preKeyId = arrayItem.value().value("prekeyid", 0);
                secInfo->deviceId = arrayItem.value().value("deviceid", "");
                secInfo->creationTime = arrayItem.value().value("timestamp", 0);
                secondaryRatchets.push_back(move(secInfo));

            }
        }

        LOGGER(DEBUGGING, __func__, " <--");
}

const string* ZinaConversation::serialize() const
{
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    json jsn;

    jsn["partner"]["name"] = partner_.getName();
    jsn["partner"]["alias"] = partner_.getAlias();

    jsn["deviceId"] = deviceId_;
    jsn["localUser"] = localUser_;
    jsn["deviceName"] = deviceName_;
    
    // b64Encode terminates the B64 string with a nul byte
    b64Encode((const uint8_t*)RK.data(), RK.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["RK"] = b64Buffer;
    
    // DHRs key pair, private, public
    if (DHRs) {
        b64Encode(DHRs->getPrivateKey().privateData(), DHRs->getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHRs"]["private"] = b64Buffer;

        b64Encode((const uint8_t*)DHRs->getPublicKey().serialize().data(), DHRs->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHRs"]["public"] = b64Buffer;
    }
    else {
        jsn["DHRs"]["private"] = "";
        jsn["DHRs"]["public"] = "";
    }
    
    // DHRr key, public
    if (DHRr) {
        b64Encode((const uint8_t*)DHRr->serialize().data(), DHRr->getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHRr"] = b64Buffer;
    }
    else {
        jsn["DHRr"] = "";
    }

    // DHIs key pair, private, public
    if (DHIs) {
        b64Encode(DHIs->getPrivateKey().privateData(), DHIs->getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHIs"]["private"] = b64Buffer;

        b64Encode((const uint8_t*)DHIs->getPublicKey().serialize().data(), DHIs->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHIs"]["public"] = b64Buffer;
    }
    else {
        jsn["DHIs"]["private"] = "";
        jsn["DHIs"]["public"] = "";
    }
    
    // DHIr key, public
    if (DHIr) {
        b64Encode((const uint8_t*)DHIr->serialize().data(), DHIr->getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["DHIr"] = b64Buffer;
    }
    else {
        jsn["DHIr"] = "";
    }

    
    // A0 key pair, private, public
    if (A0) {
        b64Encode(A0->getPrivateKey().privateData(), A0->getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["A0"]["private"] = b64Buffer;

        b64Encode((const uint8_t*)A0->getPublicKey().serialize().data(), A0->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsn["A0"]["public"] = b64Buffer;
    }
    else {
        jsn["A0"]["private"] = "";
        jsn["A0"]["public"] = "";
    }


    // The two chain keys
    b64Encode((const uint8_t*)CKs.data(), CKs.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["CKs"] = b64Buffer;

    b64Encode((const uint8_t*)CKr.data(), CKr.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["CKr"] = b64Buffer;

    jsn["Ns"] = Ns;
    jsn["Nr"] = Nr;
    jsn["PNs"] = PNs;
    jsn["preKeyId"] = preKeyId;
    jsn["ratchet"] = (ratchetFlag) ? 1 : 0;
    jsn["zrtpState"] = zrtpVerifyState;

    jsn["contextId"] = contextId;
    if (hasContextId2) {
        jsn["contextId2"] = contextId2;
    }
    jsn["versionNumber"] = versionNumber;
    jsn["identityKeyChanged"] = identityKeyChanged;

    if (!secondaryRatchets.empty()) {
        // Create and add JSON array
        json secondaries = json::array();

        for (auto&& secInfo : secondaryRatchets) {
            json secJson{
                    {"prekeyid", secInfo->preKeyId},
                    { "deviceid", secInfo->deviceId },
                    { "timestamp", secInfo->creationTime }
            };
            secondaries.push_back(secJson);
        }
        jsn["secondaries"] = secondaries;
    }
    string* data = new string(jsn.dump());

    LOGGER(DEBUGGING, __func__, " <--");
    return data;
}

void ZinaConversation::reset()
{
    LOGGER(DEBUGGING, __func__, " -->");
    DHRs.reset();
    DHRr.reset();
    DHIs.reset();
// Keep it to detect changes of the long-term identity key    delete DHIr; DHIr = NULL;
    A0.reset();

    if (!CKr.empty())
        Utilities::wipeMemory((void*)CKr.data(), CKr.size());
    CKr.clear();

    if (!CKs.empty())
        Utilities::wipeMemory((void*)CKs.data(), CKs.size());
    CKs.clear();

    if (!RK.empty())
        Utilities::wipeMemory((void*)RK.data(), RK.size());
    RK.clear();
    Nr = Ns = PNs = preKeyId = versionNumber = 0;
    ratchetFlag = false;

    // Don't reset the context id, we use its sequence number part to count re-syncs
    LOGGER(DEBUGGING, __func__, " <--");
}


JSONUnique
ZinaConversation::prepareForCapture(JSONUnique existingRoot, bool beforeAction) {
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    JSONUnique root = (existingRoot == nullptr) ? make_unique<nlohmann::json>() : move(existingRoot);

    json jsonItem;

    jsonItem["name"] = partner_.getName();
    jsonItem["alias"] = partner_.getAlias();

    jsonItem["deviceId"] = deviceId_;
    jsonItem["localUser"] = localUser_;
    jsonItem["deviceName"] = deviceName_;

    if (DHRs != nullptr) {
        b64Encode((const uint8_t*)DHRs->getPublicKey().serialize().data(), DHRs->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsonItem["DHRs"] =  b64Buffer;
    }
    else
        jsonItem["DHRs"] = "";

    // DHRr key, public
    if (DHRr != nullptr) {
        b64Encode((const uint8_t*)DHRr->serialize().data(), DHRr->getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsonItem["DHRr"] = b64Buffer;
    }
    else
        jsonItem["DHRr"] = "";

    // DHIs key, public
    if (DHIs != nullptr) {
        b64Encode((const uint8_t*)DHIs->getPublicKey().serialize().data(), DHIs->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsonItem["DHIs"] = b64Buffer;
    }
    else
        jsonItem["DHIs"] = "";

    // DHIr key, public
    if (DHIr != nullptr) {
        b64Encode((const uint8_t*)DHIr->serialize().data(), DHIr->getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsonItem["DHIr"] = b64Buffer;
    }
    else
        jsonItem["DHIr"] = "";


    // A0 key, public
    if (A0 != nullptr) {
        b64Encode((const uint8_t*)A0->getPublicKey().serialize().data(), A0->getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
        jsonItem["A0"] = b64Buffer;
    }
    else
        jsonItem["A0"] = "";

    // The two chain keys, enable only if needed to do error analysis
//    b64Encode((const uint8_t*)CKs.data(), CKs.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
//    cJSON_AddStringToObject(root, "CKs", b64Buffer);
//
//    b64Encode((const uint8_t*)CKr.data(), CKr.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
//    cJSON_AddStringToObject(root, "CKr", b64Buffer);

    jsonItem["Ns"] = Ns;
    jsonItem["Nr"] = Nr;
    jsonItem["PNs"] = PNs;
    jsonItem["ratchet"] = (ratchetFlag) ? 1 : 0;
    jsonItem["zrtpState"] = zrtpVerifyState;

    root->emplace(beforeAction ? "before" : "after", jsonItem);

    LOGGER(DEBUGGING, __func__, " <--");
    return root;
}
