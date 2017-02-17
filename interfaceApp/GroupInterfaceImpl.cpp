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

//
// Implementation of group chat
//
// Created by werner on 22.05.16.
//

#include <cryptcommon/ZrtpRandom.h>
#include "AppInterfaceImpl.h"
#include "GroupProtocol.pb.h"
#include "JsonStrings.h"
#include "../util/Utilities.h"
#include "../util/b64helper.h"
#include "../vectorclock/VectorClock.h"
#include "../vectorclock/VectorHelper.h"

using namespace std;
using namespace zina;
using namespace vectorclock;

static void fillMemberArray(cJSON* root, list<string> &members)
{
    LOGGER(INFO, __func__, " --> ");
    cJSON* memberArray;
    cJSON_AddItemToObject(root, MEMBERS, memberArray = cJSON_CreateArray());

    for (auto it = members.begin(); it != members.end(); ++it) {
        cJSON_AddItemToArray(memberArray, cJSON_CreateString(it->c_str()));
    }
    LOGGER(INFO, __func__, " <-- ");
}

static string prepareMemberList(const string &groupId, list<string> &members, const char *command) {
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_COMMAND, command);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());

    fillMemberArray(root, members);

    CharUnique out(cJSON_PrintUnformatted(root));
    string listCommand(out.get());

    return listCommand;
}

static string leaveCommand(const string& groupId, const string& memberId)
{
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, LEAVE);
    cJSON_AddStringToObject(root, MEMBER_ID, memberId.c_str());
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    return command;
}

static string newGroupCommand(const string& groupId, int32_t maxMembers)
{
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, NEW_GROUP);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddNumberToObject(root, GROUP_MAX_MEMBERS, maxMembers);

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    return command;
}

static string newGroupNameCommand(const string& groupId, const string& groupName)
{
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, NEW_NAME);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, GROUP_NAME, groupName.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    return command;
}

static string newGroupAvatarCommand(const string& groupId, const string& groupAvatar)
{
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, NEW_AVATAR);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, GROUP_AVATAR, groupAvatar.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    return command;
}

static string newGroupBurnCommand(const string& groupId, int64_t burnTime, int32_t burnMode)
{
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, NEW_BURN);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddNumberToObject(root, GROUP_BURN_SEC, burnTime);
    cJSON_AddNumberToObject(root, GROUP_BURN_MODE, burnMode);

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    return command;
}

static int32_t serializeChangeSet(const GroupChangeSet changeSet, string *attributes)
{

    string serialized;
    if (!changeSet.SerializeToString(&serialized)) {
        return GENERIC_ERROR;
    }
    size_t b64Size = static_cast<size_t>(serialized.size() * 2);
    unique_ptr<char[]> b64Buffer(new char[b64Size]);
    if (b64Encode(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), b64Buffer.get(), b64Size) == 0) {
        return GENERIC_ERROR;
    }

    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    string serializedSet;
    serializedSet.assign(b64Buffer.get());

    if (!serializedSet.empty()) {
        cJSON_AddStringToObject(root, GROUP_CHANGE_SET, serializedSet.c_str());
    }
    CharUnique out(cJSON_PrintUnformatted(root));
    attributes->assign(out.get());
    return SUCCESS;
}

// ****** Public instance functions
// *******************************************************

bool AppInterfaceImpl::modifyGroupSize(string& groupId, int32_t newSize)
{
    LOGGER(INFO, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        errorInfo_ = " Conversation store not ready.";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    int32_t result;
    shared_ptr<cJSON> group = store->listGroup(groupId, &result);
    if (!group || SQL_FAIL(result)) {
        errorInfo_ = " Cannot get group data: ";
        errorInfo_.append(groupId);
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    cJSON* root = group.get();
    string groupOwner(Utilities::getJsonString(root, GROUP_OWNER, ""));

    if (ownUser_ != groupOwner) {
        errorInfo_ = " Only owner can modify group member size";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    int32_t members = Utilities::getJsonInt(root, GROUP_MEMBER_COUNT, -1);
    if (members == -1 || members > newSize) {
        errorInfo_ = " Already more members in group than requested.";
        LOGGER(ERROR, __func__, errorInfo_, members);
        return false;

    }
    LOGGER(INFO, __func__, " <--");
    return true;
}

int32_t AppInterfaceImpl::sendGroupMessage(const string &messageDescriptor, const string &attachmentDescriptor,
                                           const string &messageAttributes) {
    string groupId;
    string msgId;
    string message;

    LOGGER(INFO, __func__, " -->");
    int32_t result = parseMsgDescriptor(messageDescriptor, &groupId, &msgId, &message);
    if (result < 0) {
        errorCode_ = result;
        LOGGER(ERROR, __func__, " Wrong JSON data to send group message, error code: ", result);
        return result;
    }
    JsonUnique sharedRoot(!messageAttributes.empty() ? cJSON_Parse(messageAttributes.c_str()) : cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string newAttributes(out);
    free(out);

    result = prepareChangeSetSend(groupId);
    if (result < 0) {
        errorCode_ = result;
        errorInfo_ = "Error preparing group change set";
        LOGGER(ERROR, __func__, " Error preparing group change set, error code: ", result);
        return result;
    }
    if (!store_->hasGroup(groupId) || ((store_->getGroupAttribute(groupId).first & ACTIVE) != ACTIVE)) {
        return NO_SUCH_ACTIVE_GROUP;
    }

    auto members = store_->getAllGroupMembers(groupId, &result);
    size_t membersFound = members->size();
    for (; !members->empty(); members->pop_front()) {
        string recipient(Utilities::getJsonString(members->front().get(), MEMBER_ID, ""));
        bool toSibling = recipient == ownUser_;
        auto preparedMsgData = prepareMessageInternal(messageDescriptor, attachmentDescriptor, newAttributes,
                                                      toSibling, GROUP_MSG_NORMAL, &result, recipient, groupId);
        if (result != SUCCESS) {
            LOGGER(ERROR, __func__, " <-- Error: ", result);
            groupUpdateSendDone(groupId);
            return result;
        }
        doSendMessages(extractTransportIds(preparedMsgData.get()));
    }
    groupUpdateSendDone(groupId);
    LOGGER(INFO, __func__, " <--, ", membersFound);
    return OK;
}

int32_t AppInterfaceImpl::groupMessageRemoved(const string& groupId, const string& messageId)
{
    if (groupId.empty() || messageId.empty()) {
        return DATA_MISSING;
    }
    JsonUnique sharedRoot(cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_COMMAND, REMOVE_MSG);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, MSG_ID, messageId.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string command(out.get());

    sendGroupCommand(ownUser_, generateMsgIdTime(), command);
    return OK;
}

// ****** Non public instance functions and helpers
// ******************************************************

int32_t AppInterfaceImpl::processGroupMessage(int32_t msgType, const string &msgDescriptor,
                                              const string &attachmentDescr, string *attributesDescr)
{
    LOGGER(INFO, __func__, " -->");

    if (msgType == GROUP_MSG_CMD) {
        return processGroupCommand(msgDescriptor, attributesDescr);
    }
    if (msgType == GROUP_MSG_NORMAL && msgDescriptor.empty()) {
        return GROUP_MSG_DATA_INCONSISTENT;
    }
    if (checkAndProcessChangeSet(msgDescriptor, attributesDescr) == SUCCESS) {
        groupMsgCallback_(msgDescriptor, attachmentDescr, *attributesDescr);
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::processGroupCommand(const string &msgDescriptor, string *commandIn)
{
    LOGGER(INFO, __func__, " --> ", *commandIn);

    if (commandIn->empty()) {
        return GROUP_CMD_MISSING_DATA;
    }
    JsonUnique sharedRoot(cJSON_Parse(commandIn->c_str()));
    cJSON* root = sharedRoot.get();

    if (Utilities::hasJsonKey(root, GROUP_CHANGE_SET)) {
        return checkAndProcessChangeSet(msgDescriptor, commandIn);
    }

    string groupCommand(Utilities::getJsonString(root, GROUP_COMMAND, ""));
    if (groupCommand.empty()) {
        return GROUP_CMD_DATA_INCONSISTENT;
    }
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));

    if (groupCommand.compare(REMOVE_MSG) == 0) {
        groupCmdCallback_(*commandIn);
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::checkAndProcessChangeSet(const string &msgDescriptor, string *messageAttributes)
{
    LOGGER(INFO, __func__, " -->");

    string changeSetString;

    JsonUnique sharedRoot(cJSON_Parse(messageAttributes->c_str()));
    cJSON* root = sharedRoot.get();
    if (Utilities::hasJsonKey(root, GROUP_CHANGE_SET)) {
        changeSetString = Utilities::getJsonString(root, GROUP_CHANGE_SET, "");

        // Remove the change set b64 data
        cJSON_DeleteItemFromObject(root, GROUP_CHANGE_SET);
        CharUnique out(cJSON_PrintUnformatted(root));
        messageAttributes->assign(out.get());
    }
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));

    // Get the message sender info
    sharedRoot = JsonUnique(cJSON_Parse(msgDescriptor.c_str()));
    root = sharedRoot.get();
    string sender(Utilities::getJsonString(root, MSG_SENDER, ""));
    string deviceId(Utilities::getJsonString(root, MSG_DEVICE_ID, ""));

    bool hasGroup = store_->hasGroup(groupId);

    // We have an empty CS here, thus only a message to a group
    if (changeSetString.empty()) {
        if (hasGroup) {
            return SUCCESS;
        }
        else {
            GroupChangeSet rmSet;
            GroupUpdateRmMember *updateRmMember = rmSet.mutable_updatermmember();
            Member *member = updateRmMember->add_rmmember();
            member->set_user_id(getOwnUser());

            string attributes;
            int32_t result = serializeChangeSet(rmSet, &attributes);
            if (result != SUCCESS) {
                return result;
            }
            // message from unknown group, ask sender to remove me
            // It's a non-user visible message, thus send it as type command. This prevents callback to UI etc.
            return sendGroupMessageToSingleUserDevice(groupId, sender, deviceId, attributes, Empty, GROUP_MSG_CMD);
        }
    }
    if (changeSetString.size() > tempBufferSize_) {
        delete[] tempBuffer_;
        tempBuffer_ = new char[changeSetString.size()];
        tempBufferSize_ = changeSetString.size();
    }
    size_t binLength = b64Decode(changeSetString.data(), changeSetString.size(), (uint8_t *) tempBuffer_,
                                 tempBufferSize_);
    if (binLength == 0) {
        LOGGER(ERROR, __func__, "Base64 decoding of group change set failed.");
        return CORRUPT_DATA;
    }

    GroupChangeSet changeSet;
    if (!changeSet.ParseFromArray(tempBuffer_, static_cast<int32_t>(binLength))) {
        LOGGER(ERROR, __func__, "ProtoBuffer decoding of group change set failed.");
        return false;
    }

    int32_t result = processReceivedChangeSet(changeSet, groupId, sender, deviceId, hasGroup);
    LOGGER(INFO, __func__, " <-- ");
    return result;
}

int32_t AppInterfaceImpl::processReceivedChangeSet(const GroupChangeSet &changeSet, const string &groupId,
                                                   const string &sender, const string &deviceId, bool hasGroup)
{
    LOGGER(INFO, __func__, " -->");

    bool fromSibling = sender == getOwnUser();

    // If all this is true then our user left the group, triggered it on a sibling device
    if (fromSibling && hasGroup &&
            changeSet.has_updatermmember() &&
            changeSet.updatermmember().rmmember_size() == 1 &&
            changeSet.updatermmember().rmmember(0).user_id() == getOwnUser()) {

        const int32_t result = processLeaveGroup(groupId, getOwnUser(), true);
        if (result != SUCCESS) {
            errorCode_ = result;
            errorInfo_ = "Sibling: cannot remove group.";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        groupCmdCallback_(leaveCommand(groupId, getOwnUser()));
        return result;
    }

    // Implicitly create a new group if it does not exist yet and we should add a member to it
    // Works the same for sibling devices and other member devices
    if (!hasGroup && changeSet.has_updateaddmember() && changeSet.updateaddmember().addmember_size() > 0) {
        string callbackCmd;
        const int32_t result = insertNewGroup(groupId, changeSet, &callbackCmd);
        if (result != SUCCESS) {
            errorCode_ = result;
            errorInfo_ = "Cannot add new group.";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        hasGroup = true;                // Now we have a group :-)
        groupCmdCallback_(callbackCmd);
    }

    GroupChangeSet ackRmSet;              // Gathers all ACKs and a remove on unexpected group change sets

    // No such group but some group related update for it? Inform sender that we don't have
    // this group and ask to remove me. To send a "remove" when receiving an ACK for an unknown
    // group, leads to message loops
    if (!hasGroup ) {
        if (changeSet.has_updateavatar() || changeSet.has_updateburn() || changeSet.has_updatename()
            || changeSet.has_updatermmember()) {

            // If we don't know this group and asked to remove ourselves from it, just ignore it. It's
            // a loop breaker in case of unusual race conditions.
            if (changeSet.updatermmember().rmmember_size() == 1 &&
                changeSet.updatermmember().rmmember(0).user_id() == getOwnUser()) {
                return SUCCESS;
            }
            GroupUpdateRmMember *updateRmMember = ackRmSet.mutable_updatermmember();
            Member *member = updateRmMember->add_rmmember();
            member->set_user_id(getOwnUser());
            LOGGER(INFO, __func__, " <-- unexpected group change set");
        }
    }
    else {
        string binDeviceId;
        makeBinaryDeviceId(deviceId, &binDeviceId);

        if (changeSet.acks_size() > 0) {
            // Process ACKs from partners and siblings
            const int32_t result = processAcks(changeSet, groupId, binDeviceId);
            if (result != SUCCESS) {
                return result;
            }
        }

        if (changeSet.has_updatename()) {
            // Update the group's name
            const int32_t result = processUpdateName(changeSet.updatename(), groupId, binDeviceId, &ackRmSet);
            if (result != SUCCESS) {
                return result;
            }
        }
        if (changeSet.has_updateavatar()) {
            // Update the group's avatar info
            const int32_t result = processUpdateAvatar(changeSet.updateavatar(), groupId, binDeviceId, &ackRmSet);
            if (result != SUCCESS) {
                return result;
            }
        }
        if (changeSet.has_updateburn()) {
            // Update the group's burn timer info
            const int32_t result = processUpdateBurn(changeSet.updateburn(), groupId, binDeviceId, &ackRmSet);
            if (result != SUCCESS) {
                return result;
            }
        }
        if ((changeSet.has_updateaddmember() && changeSet.updateaddmember().addmember_size() > 0) ||
            (changeSet.has_updatermmember() && changeSet.updatermmember().rmmember_size() > 0)) {

            const int32_t result = processUpdateMembers(changeSet, groupId, &ackRmSet);
            if (result != SUCCESS) {
                return result;
            }
        }
    }
    if (ackRmSet.acks_size() > 0 || ackRmSet.has_updatermmember()) {
        string attributes;
        int32_t result = serializeChangeSet(ackRmSet, &attributes);
        if (result != SUCCESS) {
            return result;
        }
#ifndef UNITTESTS
        // It's a non-user visible message, thus send it as type command. This prevents callback to UI etc.
        result = sendGroupMessageToSingleUserDevice(groupId, sender, deviceId, attributes, Empty, GROUP_MSG_CMD);
        if (result != SUCCESS) {
            return result;
        }
#else
        groupCmdCallback_(attributes);      // for unit testing only
#endif
    }
    LOGGER(INFO, __func__, " <-- ");
    return SUCCESS;
}

int32_t AppInterfaceImpl::processAcks(const GroupChangeSet &changeSet, const string &groupId, const string &binDeviceId)
{
    LOGGER(INFO, __func__, " -->");

    // Clean old wait-for-ack records before processing ACKs. This enables proper cleanup of pending change sets
    time_t timestamp = time(0) - MK_STORE_TIME;
    store_->cleanWaitAck(timestamp);

    const int32_t numAcks = changeSet.acks_size();

    for (int32_t i = 0; i < numAcks; i++) {
        const GroupUpdateAck &ack = changeSet.acks(i);

        const GroupUpdateType type = ack.type();
        const string &updateId = ack.update_id();
        store_->removeWaitAck(groupId, binDeviceId, updateId, type);

        // After removing an wait-for-ack record check if we still have an record for the (groupId, updateId)
        // tuple. If not then all devices sent an ack for the update types and we can remove the pending change set.
        int32_t result;
        const bool moreChangeSets = store_->hasWaitAckGroupUpdate(groupId, updateId, &result);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Error checking remaining group change sets";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        if (!moreChangeSets) {
            string key;
            key.assign(updateId).append(groupId);
            bool removed = removeFromPendingChangeSets(key);
            LOGGER(INFO, "remove groupid from pending change set: ", groupId, ": ", removed, ": ", key);
        }
    }
    LOGGER(INFO, __func__, " <-- ");
    return SUCCESS;
}

static Ordering resolveConflict(const VectorClock<string> &remoteVc, const VectorClock<string> &localVc,
                         const string &updateIdRemote, const string &updateIdLocal)
{
    const int64_t remoteSum = remoteVc.sumOfValues();
    const int64_t localSum = localVc.sumOfValues();

    if (remoteSum == localSum) {
        return updateIdRemote > updateIdLocal ? After : Before;
    }
    return remoteSum > localSum ? After : Before;
}

int32_t AppInterfaceImpl::processUpdateName(const GroupUpdateSetName &changeSet, const string &groupId,
                                            const string &binDeviceId, GroupChangeSet *ackSet)
{
    const string &updateIdRemote = changeSet.update_id();

    LOGGER(INFO, __func__, " --> ", updateIdRemote);

    VectorClock<string> remoteVc;
    deserializeVectorClock(changeSet.vclock(), &remoteVc);

    LocalVClock lvc;                    // the serialized proto-buffer representation
    VectorClock<string> localVc;

    int32_t result = readLocalVectorClock(*store_, groupId, GROUP_SET_NAME, &lvc);
    if (result == SUCCESS) {        // we may not yet have a vector clock for this group update type, thus deserialize on SUCCESS only
        deserializeVectorClock(lvc.vclock(), &localVc);
    }

    bool hasConflict = false;
    Ordering order = remoteVc.compare(localVc);
    if (order == Concurrent) {
        hasConflict = true;
        const string &updateIdLocal = lvc.update_id();
        order = resolveConflict(remoteVc, localVc, updateIdRemote, updateIdLocal);
    }

    // Remote clock is bigger than local, thus remote data is more recent than local data. Update our group
    // data, our local vector clock and return an ACK
    // In case of a conflict the conflict resolution favoured the remote data
    if (order == After) {
        const string &groupName = changeSet.name();
        result = store_->setGroupName(groupId, groupName);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot update group name";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        // Serialize and store the remote vector clock as our new local vector clock because the remote clock
        // reflects the latest changes.
        lvc.set_update_id(updateIdRemote.data(), UPDATE_ID_LENGTH);
        serializeVectorClock(remoteVc, lvc.mutable_vclock());

        result = storeLocalVectorClock(*store_, groupId, GROUP_SET_NAME, lvc);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Group set name: Cannot store new local vector clock";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        GroupUpdateAck *ack = ackSet->add_acks();
        ack->set_update_id(updateIdRemote);
        ack->set_type(GROUP_SET_NAME);
        ack->set_result(hasConflict ? ACCEPTED_CONFLICT : ACCEPTED_OK);

        groupCmdCallback_(newGroupNameCommand(groupId, groupName));
        return SUCCESS;
    }
    GroupUpdateAck *ack = ackSet->add_acks();
    ack->set_update_id(updateIdRemote);
    ack->set_type(GROUP_SET_NAME);

    // The local data is more recent than the remote data. No need to change any data, just return an ACK
    // In case of a conflict the conflict resolution favoured the local data
    if (order == Before) {
        ack->set_result(hasConflict ? REJECTED_CONFLICT : REJECTED_PAST);
        return SUCCESS;
    }
    // The local data is more recent than the remote data (remote change was _before_ ours). No need to
    // change any data, just return an ACK
    if (order == Equal) {
        ack->set_result(REJECTED_NOP);
        return SUCCESS;
    }
    return GENERIC_ERROR;
}

int32_t AppInterfaceImpl::processUpdateAvatar(const GroupUpdateSetAvatar &changeSet, const string &groupId,
                                              const string &binDeviceId, GroupChangeSet *ackSet)
{
    const string &updateIdRemote = changeSet.update_id();

    VectorClock<string> remoteVc;
    deserializeVectorClock(changeSet.vclock(), &remoteVc);

    LocalVClock lvc;                    // the serialized proto-buffer representation
    VectorClock<string> localVc;

    int32_t result = readLocalVectorClock(*store_, groupId, GROUP_SET_AVATAR, &lvc);
    if (result == SUCCESS) {        // we may not yet have a vector clock for this group update type, thus deserialize on SUCCESS only
        deserializeVectorClock(lvc.vclock(), &localVc);
    }

    bool hasConflict = false;
    Ordering order = remoteVc.compare(localVc);
    if (order == Concurrent) {
        hasConflict = true;
        const string &updateIdLocal = lvc.update_id();
        order = resolveConflict(remoteVc, localVc, updateIdRemote, updateIdLocal);
    }

    // Remote clock is bigger than local, thus remote data is more recent than local data. Update our group
    // data, our local vector clock and return an ACK
    // In case of a conflict the conflict resolution favoured the remote data
    if (order == After) {
        const string &groupAvatar = changeSet.avatar();
        result = store_->setGroupAvatarInfo(groupId, groupAvatar);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot update group avatar info";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        // Serialize and store the remote vector clock as our new local vector clock because the remote clock
        // reflects the latest changes.
        lvc.set_update_id(updateIdRemote.data(), UPDATE_ID_LENGTH);
        serializeVectorClock(remoteVc, lvc.mutable_vclock());

        result = storeLocalVectorClock(*store_, groupId, GROUP_SET_AVATAR, lvc);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Group set avatar: Cannot store new local vector clock";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        GroupUpdateAck *ack = ackSet->add_acks();
        ack->set_update_id(updateIdRemote);
        ack->set_type(GROUP_SET_AVATAR);
        ack->set_result(hasConflict ? ACCEPTED_CONFLICT : ACCEPTED_OK);

        groupCmdCallback_(newGroupAvatarCommand(groupId, groupAvatar));
        return SUCCESS;
    }
    GroupUpdateAck *ack = ackSet->add_acks();
    ack->set_update_id(updateIdRemote);
    ack->set_type(GROUP_SET_AVATAR);

    // The local data is more recent than the remote data. No need to change any data, just return an ACK
    // In case of a conflict the conflict resolution favoured the local data
    if (order == Before) {
        ack->set_result(hasConflict ? REJECTED_CONFLICT : REJECTED_PAST);
        return SUCCESS;
    }
    // The local data is more recent than the remote data (remote change was _before_ ours). No need to
    // change any data, just return an ACK
    if (order == Equal) {
        ack->set_result(REJECTED_NOP);
        return SUCCESS;
    }
    return GENERIC_ERROR;
}

int32_t AppInterfaceImpl::processUpdateBurn(const GroupUpdateSetBurn &changeSet, const string &groupId,
                                            const string &binDeviceId, GroupChangeSet *ackSet)
{
    const string &updateIdRemote = changeSet.update_id();

    VectorClock<string> remoteVc;
    deserializeVectorClock(changeSet.vclock(), &remoteVc);

    LocalVClock lvc;                    // the serialized proto-buffer representation
    VectorClock<string> localVc;

    int32_t result = readLocalVectorClock(*store_, groupId, GROUP_SET_BURN, &lvc);
    if (result == SUCCESS) {        // we may not yet have a vector clock for this group update type, thus deserialize on SUCCESS only
        deserializeVectorClock(lvc.vclock(), &localVc);
    }

    bool hasConflict = false;
    Ordering order = remoteVc.compare(localVc);

    // The vector clocks are siblings, not descendent, thus we need to resolve the conflict
    if (order == Concurrent) {
        hasConflict = true;
        const string &updateIdLocal = lvc.update_id();
        order = resolveConflict(remoteVc, localVc, updateIdRemote, updateIdLocal);
    }

    // Remote clock is bigger than local, thus remote data is more recent than local data. Update our group
    // data, our local vector clock and return an ACK
    // In case of a conflict the conflict resolution favoured the remote data
    if (order == After) {
        const int64_t burnTime = changeSet.burn_ttl_sec();
        const int32_t burnMode = changeSet.burn_mode();
        result = store_->setGroupBurnTime(groupId, burnTime, burnMode);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot update group avatar info";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        // Serialize and store the remote vector clock as our new local vector clock because the remote clock
        // reflects the latest changes.
        lvc.set_update_id(updateIdRemote.data(), UPDATE_ID_LENGTH);
        serializeVectorClock(remoteVc, lvc.mutable_vclock());

        result = storeLocalVectorClock(*store_, groupId, GROUP_SET_BURN, lvc);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Group set avatar: Cannot store new local vector clock";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        GroupUpdateAck *ack = ackSet->add_acks();
        ack->set_update_id(updateIdRemote);
        ack->set_type(GROUP_SET_BURN);
        ack->set_result(hasConflict ? ACCEPTED_CONFLICT : ACCEPTED_OK);

        groupCmdCallback_(newGroupBurnCommand(groupId, burnTime, burnMode));
        return SUCCESS;
    }
    GroupUpdateAck *ack = ackSet->add_acks();
    ack->set_update_id(updateIdRemote);
    ack->set_type(GROUP_SET_BURN);

    // The local data is more recent than the remote data. No need to change any data, just return an ACK
    // In case of a conflict the conflict resolution favoured the local data
    if (order == Before) {
        ack->set_result(hasConflict ? REJECTED_CONFLICT : REJECTED_PAST);
        return SUCCESS;
    }
    // The local data is more recent than the remote data (remote change was _before_ ours). No need to
    // change any data, just return an ACK
    if (order == Equal) {
        ack->set_result(REJECTED_NOP);
        return SUCCESS;
    }
    return GENERIC_ERROR;
}

int32_t AppInterfaceImpl::processUpdateMembers(const GroupChangeSet &changeSet, const string &groupId,
                                               GroupChangeSet *ackSet) {

    // The function first processes the add member update, then remove member. It removes member
    // from the add member list if the member is also in the remove member update.
    list<string> addMembers;
    if (changeSet.has_updateaddmember()) {
        // We always send back an ACK
        GroupUpdateAck *ack = ackSet->add_acks();
        ack->set_update_id(changeSet.updateaddmember().update_id());
        ack->set_type(GROUP_ADD_MEMBER);
        ack->set_result(ACCEPTED_OK);

        const int32_t size = changeSet.updateaddmember().addmember_size();
        for (int32_t i = 0; i < size; i++) {
            const string &name = changeSet.updateaddmember().addmember(i).user_id();
            addMembers.push_back(name);
        }
    }

    list<string> rmMembers;
    if (changeSet.has_updatermmember()) {
        // We always send back an ACK
        GroupUpdateAck *ack = ackSet->add_acks();
        ack->set_update_id(changeSet.updatermmember().update_id());
        ack->set_type(GROUP_REMOVE_MEMBER);
        ack->set_result(ACCEPTED_OK);

        const int32_t size = changeSet.updatermmember().rmmember_size();
        for (int32_t i = 0; i < size; i++) {
            const string &name = changeSet.updatermmember().rmmember(i).user_id();
            rmMembers.push_back(name);

            if (addMembers.empty()) {
                continue;
            }
            auto end = addMembers.end();
            for (auto it = addMembers.begin(); it != end; ++it) {
                if (*it == name) {
                    addMembers.erase(it);
                    break;
                }
            }
        }
    }

    // Now iterate over the add member list, check existence of the member. If we already
    // know the member, remove it from the add member list. Otherwise add it to the member table
    auto end = addMembers.end();
    for (auto it = addMembers.begin(); it != end; ) {
        int32_t result;
        bool isMember = store_->isMemberOfGroup(groupId, *it, &result);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot check group membership";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        // already a member, remove from list
        if (isMember) {
            it = addMembers.erase(it);
            continue;
        }
        result = store_->insertMember(groupId, *it);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot add new group member";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        ++it;
    }

    // Now iterate over the remove member list, check existence of the member. If we don't
    // know the member, remove it from the remove member list. Otherwise remove it from the member table
    end = rmMembers.end();
    for (auto it = rmMembers.begin(); it != end; ) {
        int32_t result;
        bool isMember = store_->isMemberOfGroup(groupId, *it, &result);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot check group membership";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        // Unknown member, no need to remove it
        if (!isMember) {
            it = rmMembers.erase(it);
            continue;
        }
        result = store_->deleteMember(groupId, *it);
        if (SQL_FAIL(result)) {
            errorCode_ = result;
            errorInfo_ = "Cannot remove group member";
            LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
            return result;
        }
        ++it;
    }
    if (!addMembers.empty()) {
        groupCmdCallback_(prepareMemberList(groupId, addMembers, ADD_MEMBERS));
    }

    if (!rmMembers.empty()) {
        groupCmdCallback_(prepareMemberList(groupId, rmMembers, RM_MEMBERS));
    }
    return SUCCESS;
}

int32_t AppInterfaceImpl::sendGroupMessageToSingleUserDevice(const string &groupId, const string &userId,
                                                       const string &deviceId, const string &attributes,
                                                       const string &msg, int32_t msgType)
{
    LOGGER(INFO, __func__, " -->");

    JsonUnique sharedRoot(!attributes.empty() ? cJSON_Parse(attributes.c_str()) : cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    CharUnique out(cJSON_PrintUnformatted(root));
    string newAttributes(out.get());

    int32_t result = prepareChangeSetSend(groupId);
    if (result < 0) {
        errorCode_ = result;
        errorInfo_ = "Error preparing group change set";
        LOGGER(ERROR, __func__, errorInfo_, "code: ", result);
        return result;
    }

    result = createChangeSetDevice(groupId, deviceId, newAttributes, &newAttributes);
    if (result < 0) {
        errorCode_ = result;
        errorInfo_ = "Cannot create and store group update records for a device";
        LOGGER(ERROR, __func__, " Cannot create and store group update records, error code: ", result);
        return result;
    }

    const string msgId = generateMsgIdTime();

    int64_t transportMsgId;
    ZrtpRandom::getRandomData(reinterpret_cast<uint8_t*>(&transportMsgId), 8);

    // The transport id is structured: bits 0..3 are status/type bits, bits 4..7 is a counter, bits 8..63 random data
    transportMsgId &= ~0xff;

    auto msgInfo = make_shared<CmdQueueInfo>();
    msgInfo->command = SendMessage;
    msgInfo->queueInfo_recipient = userId;
    msgInfo->queueInfo_deviceName = Empty;                      // Not relevant in this case, we send to a known user
    msgInfo->queueInfo_deviceId = deviceId;                     // to this user device
    msgInfo->queueInfo_msgId = msgId;
    msgInfo->queueInfo_message = createMessageDescriptor(groupId, msgId, msg);
    msgInfo->queueInfo_attachment = Empty;
    msgInfo->queueInfo_attributes = newAttributes;              // message attributes
    msgInfo->queueInfo_transportMsgId = transportMsgId | static_cast<uint64_t>(msgType);
    msgInfo->queueInfo_toSibling = userId == getOwnUser();
    msgInfo->queueInfo_newUserDevice = false;                   // known user, known device
    queuePreparedMessage(msgInfo);
    doSendSingleMessage(msgInfo->queueInfo_transportMsgId);

    LOGGER(INFO, __func__, " <-- ");
    return SUCCESS;
}


int32_t AppInterfaceImpl::sendGroupCommandToAll(const string& groupId, const string &msgId, const string &command) {
    LOGGER(INFO, __func__, " --> ");

    int32_t result;
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);
    for (; !members->empty(); members->pop_front()) {
        string recipient(Utilities::getJsonString(members->front().get(), MEMBER_ID, ""));
        sendGroupCommand(recipient, msgId, command);
        if (result != SUCCESS) {
            LOGGER(ERROR, __func__, " <-- Error: ", result);
            return result;
        }
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::sendGroupCommand(const string &recipient, const string &msgId, const string &command) {
    LOGGER(INFO, __func__, " --> ", recipient, ", ", ownUser_);

    bool toSibling = recipient == ownUser_;
    int32_t result;
    auto preparedMsgData = prepareMessageInternal(createMessageDescriptor(recipient, msgId), Empty, command, toSibling, GROUP_MSG_CMD, &result, recipient);
    if (result != SUCCESS) {
        LOGGER(ERROR, __func__, " <-- Error: ", result);
        return result;
    }
    doSendMessages(extractTransportIds(preparedMsgData.get()));

    LOGGER(INFO, __func__, " <--");
    return OK;
}


void AppInterfaceImpl::clearGroupData()
{
    LOGGER(INFO, __func__, " --> ");
    shared_ptr<list<shared_ptr<cJSON> > > groups = store_->listAllGroups();

    for (; groups && !groups->empty(); groups->pop_front()) {
        shared_ptr<cJSON>& group = groups->front();
        string groupId(Utilities::getJsonString(group.get(), GROUP_ID, ""));
        store_->deleteAllMembers(groupId);
        store_->deleteGroup(groupId);
    }
}


int32_t AppInterfaceImpl::deleteGroupAndMembers(string const& groupId)
{
    LOGGER(INFO, __func__, " --> ");

    int32_t result = store_->deleteAllMembers(groupId);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, "Could not delete all members of group: ", groupId, ", SQL code: ", result);
        // Try to deactivate group at least
        store_->clearGroupAttribute(groupId, ACTIVE);
        store_->setGroupAttribute(groupId, INACTIVE);
        return GROUP_ERROR_BASE + result;
    }
    result = store_->deleteGroup(groupId);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, "Could not delete group: ", groupId, ", SQL code: ", result);
        // Try to deactivate group at least
        store_->clearGroupAttribute(groupId, ACTIVE);
        store_->setGroupAttribute(groupId, INACTIVE);
        return GROUP_ERROR_BASE + result;
    }
    return SUCCESS;
}

// Insert data of a new group into the database. This function also adds myself as a member to the
// new group.
int32_t AppInterfaceImpl::insertNewGroup(const string &groupId, const GroupChangeSet &changeSet, string *callbackCmd) {
    const string &groupName = changeSet.has_updatename() ? changeSet.updatename().name() : Empty;

    int32_t sqlResult = store_->insertGroup(groupId, groupName, getOwnUser(), Empty, MAXIMUM_GROUP_SIZE);
    if (SQL_FAIL(sqlResult)) {
        return GROUP_ERROR_BASE + sqlResult;
    }

    // Add myself to the new group, this saves us a "send to sibling" group function.
    sqlResult = store_->insertMember(groupId, getOwnUser());
    if (SQL_FAIL(sqlResult)) {
        return GROUP_ERROR_BASE + sqlResult;
    }
    if (callbackCmd != nullptr) {
        callbackCmd->assign(newGroupCommand(groupId, MAXIMUM_GROUP_SIZE));
    }

    return SUCCESS;
}
