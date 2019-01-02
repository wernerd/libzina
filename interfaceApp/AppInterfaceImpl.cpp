/*
 * Copyright 2016 Silent Circle, LLC

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

#include <set>
#include "AppInterfaceImpl.h"

#include "../keymanagment/PreKeys.h"
#include "../keymanagment/KeyManagement.h"
#include "../util/b64helper.h"
#include "../provisioning/Provisioning.h"
#include "../provisioning/ScProvisioning.h"
#include "../dataRetention/ScDataRetention.h"
#include "JsonStrings.h"
#include "../util/Utilities.h"

#include <cryptcommon/ZrtpRandom.h>
#include <condition_variable>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"

using namespace std;
using namespace zina;
using json = nlohmann::json;

// Locks, conditional variables and flags to synchronize the functions to re-key a device
// conversation (ratchet context) and to re-scan devices.
static mutex reKeyLock;
static bool reKeyDone;

static mutex reScanLock;
static bool reScanDone;

static mutex synchronizeLock;
static condition_variable synchronizeCv;

AppInterfaceImpl::AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId,
                                   RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback,
                                   GROUP_MSG_RECV_FUNC groupMsgCallback, GROUP_CMD_RECV_FUNC groupCmdCallback,
                                   GROUP_STATE_FUNC groupStateCallback):
        AppInterface(receiveCallback, stateReportCallback, notifyCallback, groupMsgCallback, groupCmdCallback, groupStateCallback),
        tempBuffer_(nullptr), tempBufferSize_(0), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId),
        errorCode_(0), transport_(nullptr), flags_(0), siblingDevicesScanned_(false), drLrmm_(false), drLrmp_(false), drLrap_(false),
        drBldr_(false), drBlmr_(false), drBrdr_(false), drBrmr_(false)
{
    store_ = SQLiteStoreConv::getStore();
#if defined(SC_ENABLE_DR)
    ScDataRetention::setAuthorization(authorization);
#endif
}

AppInterfaceImpl::~AppInterfaceImpl()
{
    LOGGER(DEBUGGING, __func__, " -->");
    tempBufferSize_ = 0; delete tempBuffer_; tempBuffer_ = nullptr;
    delete transport_; transport_ = nullptr;
    LOGGER(DEBUGGING, __func__, " <--");
}

string AppInterfaceImpl::createSupplementString(const string& attachmentDesc, const string& messageAttrib)
{
    LOGGER(DEBUGGING, __func__, " -->");
    string supplement;
    if (!attachmentDesc.empty() || !messageAttrib.empty()) {
        json supplementJson;

        if (!attachmentDesc.empty()) {
            LOGGER(VERBOSE, "Adding an attachment descriptor supplement");
            supplementJson["a"] = attachmentDesc;
        }
        if (!messageAttrib.empty()) {
            LOGGER(VERBOSE, "Adding an message attribute supplement");
            supplementJson["m"] = messageAttrib;
        }
        supplement = supplementJson.dump();
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return supplement;
}


string* AppInterfaceImpl::getKnownUsers()
{
    int32_t sqlCode;

    LOGGER(DEBUGGING, __func__, " -->");
    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return nullptr;
    }

    auto names = store_->getKnownConversations(ownUser_, &sqlCode);

    if (SQL_FAIL(sqlCode) || !names) {
        LOGGER(INFO, __func__, " No known Axolotl conversations.");
        return nullptr;
    }
    size_t size = names->size();
    if (size == 0)
        return nullptr;

    json jsn;
    jsn["version"] = 1;

    json nameArray = json::array();
    for (const auto& name : *names) {
        nameArray += name;
    }
    jsn["users"] = nameArray;
    string* retVal = new string(jsn.dump());

    LOGGER(DEBUGGING, __func__, " <--");
    return retVal;
}

/*
 * JSON data for a registration request:
{
    "version" :        <int32_t>,        # Version of JSON registration, 1 for the first implementation
    "identity_key" :    <string>,         # public part encoded base64 data 
    "prekeys" : [{
        "id" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    },
    ....
    {
        "id" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    }]
}
 */
int32_t AppInterfaceImpl::registerZinaDevice(string* result)
{
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    LOGGER(DEBUGGING, __func__, " -->");

    json jsn;
    jsn["version"] = 1;
//    cJSON_AddStringToObject(root, "scClientDevId", scClientDevId_.c_str());

    auto ownConv = ZinaConversation::loadLocalConversation(ownUser_, *store_);
    if (!ownConv->isValid()) {
        LOGGER(ERROR, __func__, " No own conversation in database.");
        return NO_OWN_ID;
    }
    if (!ownConv->hasDHIs()) {
        LOGGER(ERROR, __func__, " Own conversation not correctly initialized.");
        return NO_OWN_ID;
    }

    const DhKeyPair& myIdPair = ownConv->getDHIs();
    string data = myIdPair.getPublicKey().serialize();

    b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    jsn["identity_key"] = b64Buffer;

    json jsonPkrArray = json::array();

    // Due to a little asymmetry of the SC provisioning API we need to do some trick here to use
    // the new key management API:
    // - get an *empty* Server API implementation, i.e. an implementation that does *not* store
    //   anything on the server
    // - call the KeyManagement function to generate a first set of pre-keys and store it in the
    //   database, using the empty server API -> thus does not affect the server's DB
    // - get all the stored pre-keys from the database, construct the JSON for the REST API as
    //   usual.
    // NOTE: we could also use the KeyManagement::createInitialSet(), however this also creates
    // a signed pre-key and signed pre-keys are not yet supported within Zina.

    KeyProvisioningServerApi kps;                       // this is an *empty* implementation
    KeyManagement::addNewPreKeys(NUM_PRE_KEYS, ownUser_, scClientDevId_, myIdPair.getPublicKey(), kps, *store_);

    std::list<PreKeyDataUnique> keyList;
    KeyManagement::getAllOneTimeFromDb(keyList, *store_);

    for (auto& preKey : keyList) {
        json pkrObject;
        pkrObject["id"] = preKey->keyId;

        // Get pre-key's public key data, serialized
        const string keyData = preKey->keyPair->getPublicKey().serialize();
        b64Encode((const uint8_t*) keyData.data(), keyData.size(), b64Buffer, MAX_KEY_BYTES_ENCODED * 2);
        pkrObject["key"] = b64Buffer;

        jsonPkrArray += pkrObject;
    }
    jsn["prekeys"] = jsonPkrArray;

    int32_t code = Provisioning::registerZinaDevice(jsn.dump(), authorization_, scClientDevId_, result);
    if (code != 200) {
        LOGGER(ERROR, __func__, "Failed to register device for ZINA usage, code: ", code);
    }
    else {
        LOGGER(DEBUGGING, __func__, " <-- ", code);
    }
    return code;
}

int32_t AppInterfaceImpl::removeZinaDevice(string& devId, string* result)
{
    LOGGER(DEBUGGING, __func__, " <-->");
    return ScProvisioning::removeZinaDevice(devId, authorization_, result);
}

int32_t AppInterfaceImpl::newPreKeys(int32_t number)
{
    LOGGER(DEBUGGING, __func__, " -->");

    auto conv = ZinaConversation::loadLocalConversation(ownUser_, *store_);
    const DhPublicKey& identity = conv->getDHIs().getPublicKey();

    ScProvisioning provisioning(authorization_);  // implements the server API, select another class here

    return KeyManagement::addNewPreKeys(number, ownUser_, scClientDevId_, identity, provisioning, *store_);
}

int32_t AppInterfaceImpl::getNumPreKeys() const
{
    LOGGER(DEBUGGING, __func__, " <-->");
    ScProvisioning provisioning(authorization_);

    return KeyManagement::getNumberAvailableKeysOnServer(ownUser_, scClientDevId_, provisioning);
}

// Get known Zina device from provisioning server, check if we have a new one
// and if yes send a "ping" message to the new devices to create an Axolotl conversation
// for the new devices. The real implementation is in the command handling function below.

void AppInterfaceImpl::rescanUserDevices(const string& userName)
{
    LOGGER(DEBUGGING, __func__, " -->");

    // Only _one_ re-scan command at a time because we check on one Done condition only
    unique_lock<mutex> reScan(reScanLock);
    reScanDone = false;

    auto msgInfo = new CmdQueueInfo;
    msgInfo->command = ReScanUserDevices;
    msgInfo->queueInfo_recipient = userName;

    unique_lock<mutex> syncCv(synchronizeLock);
    addMsgInfoToRunQueue(unique_ptr<CmdQueueInfo>(msgInfo));

    while (!reScanDone) {
        synchronizeCv.wait(syncCv);
    }
    LOGGER(DEBUGGING, __func__, " <--");
}


void AppInterfaceImpl::setHttpHelper(HTTP_FUNC httpHelper)
{
    ScProvisioning::setHttpHelper(httpHelper);
#if defined(SC_ENABLE_DR)
    ScDataRetention::setHttpHelper(httpHelper);
#endif
}

#if defined(SC_ENABLE_DR)
void AppInterfaceImpl::setS3Helper(S3_FUNC s3Helper)
{
    ScDataRetention::setS3Helper(s3Helper);
}
#endif

void AppInterfaceImpl::reKeyAllDevices(const string &userName) {
    list<StringUnique> devices;

    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return;
    }
    store_->getLongDeviceIds(userName, ownUser_, devices);
    for (auto &recipientDeviceId : devices) {
        reKeyDevice(userName, *recipientDeviceId);
    }
}

void AppInterfaceImpl::reKeyDevice(const string &userName, const string &deviceId) {
    LOGGER(DEBUGGING, __func__, " -->");

    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return;
    }
    // Don't re-sync this device
    bool toSibling = userName == ownUser_;
    if (toSibling && deviceId == scClientDevId_) {
        return;
    }

    // Only _one_ re-key command at a time because we check on one Done condition only
#if !defined(EMSCRIPTEN)
    unique_lock<mutex> reKey(reKeyLock);
#endif
    reKeyDone = false;

    auto msgInfo = new CmdQueueInfo;
    msgInfo->command = ReKeyDevice;
    msgInfo->queueInfo_recipient = userName;
    msgInfo->queueInfo_deviceId = deviceId;
    msgInfo->boolData1 = toSibling;

    unique_lock<mutex> syncCv(synchronizeLock);
    addMsgInfoToRunQueue(unique_ptr<CmdQueueInfo>(msgInfo));
#if !defined(EMSCRIPTEN)
    while (!reKeyDone) {
        synchronizeCv.wait(syncCv);
    }
#endif
    LOGGER(DEBUGGING, __func__, " <--");
}

// ***** Private functions
// *******************************

int32_t AppInterfaceImpl::parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message, bool receivedMsg)
{
    LOGGER(DEBUGGING, __func__, " -->");

    // wrap the cJSON root into a shared pointer with custom cJSON deleter, this
    // will always free the cJSON root when we leave the function :-) .

    json jsn;
    try {
        jsn = json::parse(messageDescriptor);
    } catch(json::exception& e) {
        errorInfo_ = "root";
        return GENERIC_ERROR;
    }
    const char* recipientSender = receivedMsg ? MSG_SENDER : MSG_RECIPIENT;

    recipient->assign(jsn.value(recipientSender, ""));
    if (recipient->empty()) {
        errorInfo_ = recipientSender;
        return JS_FIELD_MISSING;
    }

    // Get the message id
    msgId->assign(jsn.value(MSG_ID, ""));
    if (msgId->empty()) {
        errorInfo_ = MSG_ID;
        return JS_FIELD_MISSING;
    }

    // Get the message
    if (jsn.find(MSG_MESSAGE) == jsn.end()) {
        errorInfo_ = MSG_MESSAGE;
        return JS_FIELD_MISSING;
    }
    message->assign(jsn.at(MSG_MESSAGE).get<string>());

    LOGGER(DEBUGGING, __func__, " <--");
    return OK;
}

string AppInterfaceImpl::getOwnIdentityKey()
{
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5
    shared_ptr<ZinaConversation> axoConv = ZinaConversation::loadLocalConversation(ownUser_, *store_);
    if (!axoConv->isValid()) {
        LOGGER(ERROR, "No own conversation, ignore.")
        LOGGER(INFO, __func__, " <-- No own conversation.");
        errorInfo_ = "Failed to read own conversation from database";
        errorCode_ = axoConv->getErrorCode();
        return Empty;
    }

    const DhPublicKey& pubKey = axoConv->getDHIs().getPublicKey();

    b64Encode(pubKey.getPublicKeyPointer(), pubKey.getSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);

    string idKey((const char*)b64Buffer);
    idKey.append(":");
    if (!axoConv->getDeviceName().empty()) {
        idKey.append(axoConv->getDeviceName());
    }
    idKey.append(":").append(scClientDevId_).append(":0");
    LOGGER(DEBUGGING, __func__, " <--");
    return idKey;
}

shared_ptr<list<string> > AppInterfaceImpl::getIdentityKeys(string& user)
{
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5
    shared_ptr<list<string> > idKeys = make_shared<list<string> >();

    list<StringUnique> devices;
    store_->getLongDeviceIds(user, ownUser_, devices);

    for (auto &recipientDeviceId : devices) {
        auto axoConv = ZinaConversation::loadConversation(ownUser_, user, *recipientDeviceId, *store_);
        errorCode_ = axoConv->getErrorCode();
        if (errorCode_ != SUCCESS || !axoConv->isValid()) { // A database problem when loading the conversation
            errorInfo_ = "Failed to read remote conversation from database";
            idKeys->clear();                // return an empty list, all gathered info may be invalid
            return idKeys;
        }
        if (!axoConv->hasDHIr()) {
            continue;
        }
        const DhPublicKey &idKey = axoConv->getDHIr();

        b64Encode(idKey.getPublicKeyPointer(), idKey.getSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);

        string id((const char*)b64Buffer);
        id.append(":");
        if (!axoConv->getDeviceName().empty()) {
            id.append(axoConv->getDeviceName());
        }
        id.append(":").append(*recipientDeviceId);
        snprintf(b64Buffer, 5, ":%d", axoConv->getZrtpVerifyState());
        b64Buffer[4] = '\0';          // make sure it's terminated
        id.append(b64Buffer);

        idKeys->push_back(id);
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return idKeys;
}


void AppInterfaceImpl::reKeyDeviceCommand(const CmdQueueInfo &command) {
    LOGGER(DEBUGGING, __func__, " -->");

    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " ZINA conversation DB not ready.");
        sendActionCallback(ReKeyAction);
        return;
    }
    // clear data and store the nearly empty conversation
    auto conv = ZinaConversation::loadConversation(ownUser_, command.queueInfo_recipient, command.queueInfo_deviceId, *store_);
    if (!conv->isValid()) {
        sendActionCallback(ReKeyAction);
        return;
    }
    conv->reset();
    int32_t result = conv->storeConversation(*store_);
    if (result != SUCCESS) {
        sendActionCallback(ReKeyAction);
        return;
    }

    // Check if server still knows this device.
    // If no device at all for his user -> remove all conversations (ratchet contexts) of this user.
    list<pair<string, string> > devices;
    result = Provisioning::getZinaDeviceIds(command.queueInfo_recipient, authorization_, devices);

    if (result != SUCCESS || devices.empty()) {
        store_->deleteConversationsName(command.queueInfo_recipient, ownUser_);
        sendActionCallback(ReKeyAction);
        return;
    }

    string deviceName;
    bool deviceFound = false;
    for (const auto &device : devices) {
        if (command.queueInfo_deviceId == device.first) {
            deviceName = device.second;
            deviceFound = true;
            break;
        }
    }

    // The server does not know this device anymore. In this case remove the conversation (ratchet context), done.
    if (!deviceFound) {
        store_->deleteConversation(command.queueInfo_recipient, command.queueInfo_deviceId, ownUser_);
        sendActionCallback(ReKeyAction);
        return;
    }
    queueMessageToSingleUserDevice(command.queueInfo_recipient, generateMsgIdTime(), command.queueInfo_deviceId,
                                   deviceName, ping, Empty, Empty, MSG_CMD, true, ReKeyAction);
    LOGGER(DEBUGGING, __func__, " <--");
}

void AppInterfaceImpl::setIdKeyVerified(const string &userName, const string& deviceId, bool flag) {
    LOGGER(DEBUGGING, __func__, " -->");

    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return;
    }
    // Don't do this for own devices
    bool toSibling = userName == ownUser_;
    if (toSibling && deviceId == scClientDevId_)
        return;

    auto msgInfo = new CmdQueueInfo;
    msgInfo->command = SetIdKeyChangeFlag;
    msgInfo->queueInfo_recipient = userName;
    msgInfo->queueInfo_deviceId = deviceId;
    msgInfo->boolData1 = flag;
    addMsgInfoToRunQueue(unique_ptr<CmdQueueInfo>(msgInfo));

    LOGGER(DEBUGGING, __func__, " <--");
}

int32_t AppInterfaceImpl::setDataRetentionFlags(const string& jsonFlags)
{
    LOGGER(DEBUGGING, __func__, " --> ", jsonFlags);

#if defined(SC_ENABLE_DR)
    if (jsonFlags.empty()) {
        return DATA_MISSING;
    }

    shared_ptr<cJSON> sharedRoot(cJSON_Parse(jsonFlags.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    if (root == nullptr) {
        return CORRUPT_DATA;
    }
    drLrmm_ = Utilities::getJsonBool(root, LRMM, false);
    drLrmp_ = Utilities::getJsonBool(root, LRMP, false);
    drLrap_ = Utilities::getJsonBool(root, LRAP, false);
    drBldr_ = Utilities::getJsonBool(root, BLDR, false);
    drBlmr_ = Utilities::getJsonBool(root, BLMR, false);
    drBrdr_ = Utilities::getJsonBool(root, BRDR, false);
    drBrmr_ = Utilities::getJsonBool(root, BRMR, false);
#endif
    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}

void AppInterfaceImpl::checkRemoteIdKeyCommand(const CmdQueueInfo &command)
{
    /*
     * Command data usage:
    command.command = CheckRemoteIdKey;
    command.stringData1 = remoteName;
    command.stringData2 = deviceId;
    command.stringData3 = pubKey;
    command.int32Data = verifyState;
     */
    auto remote = ZinaConversation::loadConversation(getOwnUser(), command.stringData1, command.stringData2, *store_);

    if (!remote->isValid()) {
        LOGGER(ERROR, "<-- No conversation, user: '", command.stringData1, "', device: ", command.stringData2);
        return;
    }
    if (!remote->hasDHIr()) {
        LOGGER(ERROR, "<-- User: '", command.stringData1, "' has no longer term identity key");

    }
    const string remoteIdKey = remote->getDHIr().getPublicKey();

    if (command.stringData3 != remoteIdKey) {
        LOGGER(ERROR, "<-- Messaging keys do not match, user: '", command.stringData1, "', device: ", command.stringData2);
        return;
    }
    // if verifyState is 1 then both users verified their SAS and thus set the Axolotl conversation
    // to fully verified, otherwise at least the identity keys are equal and we proved that via
    // a ZRTP session.
    int32_t verify = (command.int32Data == 1) ? 2 : 1;
    remote->setZrtpVerifyState(verify);
    remote->setIdentityKeyChanged(false);
    remote->storeConversation(*store_);
}

void AppInterfaceImpl::setIdKeyVerifiedCommand(const CmdQueueInfo &command)
{
    /*
     * Command data usage:
    command.command = SetIdKeyChangeFlag;
    command.queueInfo_recipient = remoteName;
    command.queueInfo_deviceId = deviceId;
    command.boolData1 = flag;
     */
    auto remote = ZinaConversation::loadConversation(getOwnUser(), command.queueInfo_recipient, command.queueInfo_deviceId, *store_);

    if (!remote->isValid()) {
        LOGGER(ERROR, "<-- No conversation, user: '", command.queueInfo_recipient, "', device: ", command.queueInfo_deviceId);
        return;
    }
    remote->setIdentityKeyChanged(command.boolData1);
    remote->storeConversation(*store_);
}

void AppInterfaceImpl::rescanUserDevicesCommand(const CmdQueueInfo &command)
{
    LOGGER(DEBUGGING, __func__, " -->");

    const string &userName = command.queueInfo_recipient;

    list<pair<string, string> > devices;
    int32_t errorCode = Provisioning::getZinaDeviceIds(userName, authorization_, devices);

    if (errorCode != SUCCESS) {
        sendActionCallback(ReScanAction);
        return;
    }

    // Get known devices from DB, compare with devices from provisioning server
    // and remove old devices and their data, i.e. devices not longer known to provisioning server
    // If device list from provisioning server is empty the following loop removes _all_
    // devices and contexts of the user.
    list<StringUnique> devicesDb;

    store_->getLongDeviceIds(userName, ownUser_, devicesDb);

    for (const auto &devIdDb : devicesDb) {
        bool found = false;

        for (const auto &device : devices) {
            if (*devIdDb == device.first) {
                found = true;
                break;
            }
        }
        if (!found) {
            auto conv = ZinaConversation::loadConversation(ownUser_, userName, *devIdDb, *store_);
            if (conv) {
                conv->deleteSecondaryRatchets(*store_);
            }
            store_->deleteConversation(userName, *devIdDb, ownUser_);
            LOGGER(INFO, __func__, "Remove device from database: ", *devIdDb);
        }
    }

    // Prepare and send this to the new learned device:
    // - an Empty message
    // - a message command attribute with a ping command
    // For each Ping message the code generates a new UUID

    // Prepare the messages for all known new devices of this user

    uint64_t counter = 0;

    string deviceId;
    string deviceName;

    for (const auto &device : devices) {
        deviceId = device.first;
        deviceName = device.second;

        // Don't re-scan own device, just check if name changed
        bool toSibling = userName == ownUser_;
        if (toSibling && scClientDevId_ == deviceId) {
            shared_ptr<ZinaConversation> conv = ZinaConversation::loadLocalConversation(ownUser_, *store_);
            if (conv->isValid()) {
                const string &convDevName = conv->getDeviceName();
                if (deviceName != convDevName) {
                    conv->setDeviceName(deviceName);
                    conv->storeConversation(*store_);
                }
            }
            continue;
        }

        // If we already have a conversation for this device skip further processing
        // after storing a user defined device name. The user may change a device's name
        // using the Web interface of the provisioning server
        if (store_->hasConversation(userName, deviceId, ownUser_)) {
            auto conv = ZinaConversation::loadConversation(ownUser_, userName, deviceId, *store_);
            if (conv->isValid()) {
                const string &convDevName = conv->getDeviceName();
                if (deviceName != convDevName) {
                    conv->setDeviceName(deviceName);
                    conv->storeConversation(*store_);
                }
            }
            continue;
        }

        LOGGER(INFO, __func__, "Send Ping to new found device: ", deviceId);
        queueMessageToSingleUserDevice(userName, generateMsgIdTime(), deviceId, deviceName, ping, Empty, Empty, MSG_CMD,
                                       true, NoAction);

        performGroupHellos(userName, deviceId, deviceName);
        counter++;

        LOGGER(DEBUGGING, "Queued message to ping a new device.");
    }
    // If we found at least on new device: re-send the Ping to the last device found with a callback action,
    // then return, send callback function handles unlock/synchronize actions. Sending a Ping a second time does
    // not do any harm. We do this to signal: done with rescanning devices.
    if (counter > 0) {
        queueMessageToSingleUserDevice(userName, generateMsgIdTime(), deviceId, deviceName, ping, Empty, Empty, MSG_CMD,
                                       true, ReScanAction);
        LOGGER(DEBUGGING, __func__, " <--");
        return;
    }

    // No new devices found, unlock/sync and return
    sendActionCallback(ReScanAction);
    LOGGER(DEBUGGING, __func__, " <-- no re-scan necessary");
}

void AppInterfaceImpl::queueMessageToSingleUserDevice(const string &userId, const string &msgId, const string &deviceId,
                                                      const string &deviceName, const string &attributes, const string &attachment,
                                                      const string &msg, int32_t msgType, bool newDevice,
                                                      SendCallbackAction sendCallbackAction)
{
    LOGGER(DEBUGGING, __func__, " --> ");

    uint64_t transportMsgId;
    ZrtpRandom::getRandomData(reinterpret_cast<uint8_t*>(&transportMsgId), 8);

    // The transport id is structured: bits 0..3 are status/type bits, bits 4..7 is a counter, bits 8..63 random data
    transportMsgId &= ~0xff;

    auto msgInfo = new CmdQueueInfo;
    msgInfo->command = SendMessage;
    msgInfo->queueInfo_recipient = userId;
    msgInfo->queueInfo_deviceName = deviceName;
    msgInfo->queueInfo_deviceId = deviceId;                     // to this user device
    msgInfo->queueInfo_msgId = msgId;
    msgInfo->queueInfo_message = msg;
    msgInfo->queueInfo_attachment = attachment;
    msgInfo->queueInfo_attributes = attributes;                 // message attributes
    msgInfo->queueInfo_transportMsgId = transportMsgId | msgType;
    msgInfo->queueInfo_toSibling = userId == getOwnUser();
    msgInfo->queueInfo_newUserDevice = newDevice;
    msgInfo->queueInfo_callbackAction = sendCallbackAction;
    addMsgInfoToRunQueue(unique_ptr<CmdQueueInfo>(msgInfo));

    LOGGER(INFO, __func__, " Queued message to device: ", deviceId, ", attributes: ", attributes);

    LOGGER(DEBUGGING, __func__, " <-- ");
}

void AppInterfaceImpl::sendActionCallback(SendCallbackAction sendCallbackAction)
{
    unique_lock<mutex> syncLock(synchronizeLock);
    switch (sendCallbackAction) {
        case NoAction:
            return;

        case ReKeyAction:
            reKeyDone = true;
            break;

        case ReScanAction:
            reScanDone = true;
            break;

        default:
            LOGGER(WARNING, __func__, " Unknown send action callback code: ", sendCallbackAction);
            return;
    }
    synchronizeCv.notify_one();
}
#pragma clang diagnostic pop
