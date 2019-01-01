//
// Created by werner on 05.05.16.
//

#include "MessageCapture.h"
#include "sqlite/SQLiteStoreConv.h"
#include "../logging/ZinaLogging.h"
#include "../Constants.h"

const static char* FIELD_LATITUDE = "la";
const static char* FIELD_LONGITUDE = "lo";
const static char* FIELD_TIME = "t";
const static char* FIELD_ALTITUDE = "a";
const static char* FIELD_ACCURACY_HORIZONTAL = "v";
const static char* FIELD_ACCURACY_VERTICAL = "h";

using namespace std;
using namespace zina;

static int32_t filterAttributes(const string& attributes, string *filteredAttributes)
{
    LOGGER(DEBUGGING, __func__, " -->");

    nlohmann::json jsn;
    try {
        jsn = nlohmann::json::parse(attributes);
        jsn.erase(FIELD_LATITUDE);
        jsn.erase(FIELD_LONGITUDE);
        jsn.erase(FIELD_TIME);
        jsn.erase(FIELD_ALTITUDE);
        jsn.erase(FIELD_ACCURACY_HORIZONTAL);
        jsn.erase(FIELD_ACCURACY_VERTICAL);
    } catch (nlohmann::json::exception& e ) {
        return CORRUPT_DATA;
    }
    filteredAttributes->append(jsn.dump());

    LOGGER(DEBUGGING, __func__ , " <-- ");
    return OK;
}

static void cleanupTrace(SQLiteStoreConv &store )
{
    // Cleanup old traces, currently using the same time as for the Message Key cleanup
    time_t timestamp = time(nullptr) - MK_STORE_TIME;
    store.deleteMsgTrace(timestamp);
}

int32_t MessageCapture::captureReceivedMessage(const string &sender, const string &messageId, const string &deviceId,
                                               const string &convState, const string &attributes, bool attachments,
                                               SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__ , " -->");

    LOGGER_BEGIN(INFO)
        string filteredAttributes;
        int32_t result = filterAttributes(attributes, &filteredAttributes);
        if (result < 0) {
            LOGGER(ERROR, __func__, " Cannot parse received message attributes: ", attributes);
            return result;
        }

        result = store.insertMsgTrace(sender, messageId, deviceId, convState, filteredAttributes, attachments, true);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, " <-- Cannot store received message trace data.", result);
            return result;
        }
    LOGGER_END
    cleanupTrace(store);
    LOGGER(DEBUGGING, __func__ , " <-- ");
    return SUCCESS;
}

int32_t MessageCapture::captureSendMessage(const string &receiver, const string &messageId,const string &deviceId,
                                           const string &convState, const string &attributes, bool attachments,
                                           SQLiteStoreConv &store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    LOGGER_BEGIN(INFO)
        string filteredAttributes;
        int32_t result = filterAttributes(attributes, &filteredAttributes);
        if (result < 0) {
            LOGGER(ERROR, __func__, " Cannot parse sent message attributes: ", attributes);
            return result;
        }

        result = store.insertMsgTrace(receiver, messageId, deviceId, convState, filteredAttributes, attachments, false);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, " <-- Cannot store sent message trace data.", result);
            return result;
        }
    LOGGER_END
    cleanupTrace(store);
    LOGGER(DEBUGGING, __func__ , " <-- ");
    return SUCCESS;
}

int32_t MessageCapture::loadCapturedMsgs(const string &name, const string &messageId,
                                         const string &deviceId, SQLiteStoreConv &store,
                                         list<StringUnique> &traceRecords)
{
    return store.loadMsgTrace(name, messageId, deviceId, traceRecords);
}


