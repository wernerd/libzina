#include "SipTransport.h"
#include "../../storage/sqlite/SQLiteStoreConv.h"
#include <iostream>
#include <map>


using namespace axolotl;

void Log(const char* format, ...);

vector< int64_t >* SipTransport::sendAxoMessage(const string& recipient, vector< pair< string, string > >* msgPairs)
{
    size_t numPairs = msgPairs->size();

    uint8_t** names = new uint8_t*[numPairs+1];
    uint8_t** devIds = new uint8_t*[numPairs+1];
    uint8_t** envelopes = new uint8_t*[numPairs+1];
    size_t*   sizes = new size_t[numPairs+1];
    uint64_t* msgIds = new uint64_t[numPairs+1];

    size_t index = 0;
    for(; index < numPairs; index++) {
        pair<string, string>& msgPair = msgPairs->at(index);
        names[index] = (uint8_t*)recipient.c_str();
        devIds[index] = (uint8_t*)msgPair.first.c_str();
        envelopes[index] = (uint8_t*)msgPair.second.data();
        sizes[index] = msgPair.second.size();
    }
    names[index] = NULL; devIds[index] = NULL; envelopes[index] = NULL; 

    sendAxoData_(names, devIds, envelopes, sizes, msgIds);

    // This should clear everything because no pointers involved
    msgPairs->clear();
    delete names; delete devIds; delete envelopes; delete sizes;

    vector<int64_t>* msgIdsReturn = new std::vector<int64_t>;
    for (int32_t i = 0; i < numPairs; i++) {
        if (msgIds[i] != 0)
            msgIdsReturn->push_back(msgIds[i]);
    }
    delete msgIds;
    return msgIdsReturn;
}

int32_t SipTransport::receiveAxoMessage(uint8_t* data, size_t length)
{
    string envelope((const char*)data, length);
    int32_t result = appInterface_->receiveMessage(envelope);

    return result;
}

int32_t SipTransport::receiveAxoMessage(uint8_t* data, size_t length, uint8_t* uid,  size_t uidLen,
                                        uint8_t* primaryAlias, size_t aliasLen)
{
    string envelope((const char*)data, length);

    string uidString;
    if (uid != NULL && uidLen > 0)
        uidString.assign((const char*)uid, uidLen);

    string aliasString;
    if (primaryAlias != NULL && aliasLen > 0)
        aliasString.assign((const char*)primaryAlias, aliasLen);

    int32_t result = appInterface_->receiveMessage(envelope, uidString, aliasString);

    return result;
}

void SipTransport::stateReportAxo(int64_t messageIdentifier, int32_t stateCode, uint8_t* data, size_t length)
{
    std::string info;
    if (data != NULL) {
        info.assign((const char*)data, length);
    }
    appInterface_->stateReportCallback_(messageIdentifier, stateCode, info);
}

static string Zeros("00000000000000000000000000000000");
static map<string, string> seenIdStringsForName;

void SipTransport::notifyAxo(uint8_t* data, size_t length)
{
    string info((const char*)data, length);
    /*
     * notify call back from SIP:
     *   - parse data from SIP, get name and devices
     *   - check for new devices (store->hasConversation() )
     *   - if a new device was found call appInterface_->notifyCallback(...)
     *     NOTE: the notifyCallback function in app should return ASAP, queue/trigger actions only
     *   - done
     */

    size_t found = info.find(':');
    if (found == string::npos)        // No colon? No name -> return
        return;

    string name = info.substr(0, found);
    size_t foundAt = name.find('@');
    if (foundAt != string::npos) {
        name = name.substr(0, foundAt);
    }

    string devIds = info.substr(found + 1);
    string devIdsSave(devIds);

    // This is a check if the SIP server already send the same notify string for a name
    map<string, string>::iterator it;
    it = seenIdStringsForName.find(name);
    if (it != seenIdStringsForName.end()) {
        // Found an entry, check if device ids match, if yes -> return, already processed,
        // if no -> delete the entry, continue processing which will add the new entry.
        if (it->second == devIdsSave) {
            return;
        }
        else {
            seenIdStringsForName.erase(it);
        }
    }
    pair<map<string, string>::iterator, bool> ret;
    ret = seenIdStringsForName.insert(pair<string, string>(name, devIdsSave));
    if (!ret.second) {
        Log("Inserting of notified device ids failed: %s (%s)", name.c_str(), devIdsSave.c_str());
    }

    size_t pos = 0;
    string devId;
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();

    bool newDevice = false;
    int32_t numReportedDevices = 0;
    while ((pos = devIds.find(';')) != string::npos) {
        devId = devIds.substr(0, pos);
        devIds.erase(0, pos + 1);
        if (Zeros.compare(0, devId.size(), devId) == 0) {
            continue;
        }
        numReportedDevices++;
        if (!store->hasConversation(name, devId, appInterface_->getOwnUser())) {
            newDevice = true;
            break;
        }
    }
//     list<string>* devicesDb = store->getLongDeviceIds(name, appInterface_->getOwnUser());
//     int32_t numKnownDevices = devicesDb->size();
//     delete devicesDb;

//    Log("++++ number of devices: reported: %d, known: %d", numReportedDevices, numKnownDevices);

    if (newDevice /*|| numKnownDevices != numReportedDevices*/) {
//        Log("++++ calling notify callback");
        appInterface_->notifyCallback_(AppInterface::DEVICE_SCAN, name, devIdsSave);
    }
}

