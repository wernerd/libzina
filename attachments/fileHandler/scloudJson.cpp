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
#include "../utilities.h"
#include "../../util/b64helper.h"
#include "../../util/Utilities.h"
#include "scloud.h"
#include "scloudPriv.h"
#include "../../storage/sqlite/SQLiteStoreConv.h"


static const char* kVersionStr      = "version";
static const char* kCurrentVersionStr = "current";
static const char* kKeySuiteStr     = "keySuite";
static const char* kSymKeyStr       = "symkey";
static const char* kHashStr         = "hash";


#define _base(x) ((x >= '0' && x <= '9') ? '0' : \
(x >= 'a' && x <= 'f') ? 'a' - 10 : \
(x >= 'A' && x <= 'F') ? 'A' - 10 : \
'\255')
#define HEXOF(x) (x - _base(x))

using namespace std;
using namespace zina;
using json = nlohmann::json;


SCLError scloudDeserializeKey(uint8_t *inData, size_t inLen, SCloudKey *keyOut)
{
    string in(reinterpret_cast<char*>(inData), inLen);
    json j;

    try {
        j = json::parse(in);
    } catch(json::parse_error&) {
        return kSCLError_BadParams;
    }

    int32_t version = j.value(kCurrentVersionStr, -1);

    // If no current version then check version, backward compatibility.
    if (version == -1) {
        version = j.value(kVersionStr, -1);
    }
    if (version < kSCloudMinProtocolVersion) {
        return kSCLError_BadParams;
    }
    keyOut->keyVersion = version;

    int32_t suite = j.value(kKeySuiteStr, -1);
    keyOut->keySuite = (SCloudKeySuite)suite;

    const auto jsString = j.value(kSymKeyStr, "");
    if (jsString.empty()) {
        return kSCLError_BadParams;
    }

    size_t stringLen = jsString.size();
    switch (keyOut->keySuite) {
        case kSCloudKeySuite_AES128:
            if(stringLen != (16 + 16) * 2) {   // 128 bit key, 16 bytes block size, as bin2hex
                return kSCLError_BadParams;
            }
            keyOut->blockLength = 16;
            break;

        case kSCloudKeySuite_AES256:
            if(stringLen != (32 + 16) * 2) {   // 256 bit key, 16 bytes block size, as bin2hex
                return kSCLError_BadParams;
            }
            keyOut->blockLength = 16;
            break;

        default:
            return kSCLError_BadParams;
    }

    const char  *p;
    size_t count;
    for (count = 0, p = jsString.data(); count < stringLen && p && *p; p += 2, count += 2) {
            keyOut->symKey[(p - jsString.data()) >> 1] = static_cast<uint8_t>(((HEXOF(*p)) << 4) + HEXOF(*(p+1)));
    }
    if (version == 3) {
        const auto hash = j.value(kHashStr, "");
        if (hash.empty())
            return kSCLError_BadParams;

        size_t b64Length = hash.size();
        if (b64Length > 0)
            b64Decode(hash.data(), b64Length, keyOut->hash, SKEIN256_DIGEST_LENGTH);
    }
    keyOut->symKeyLen = count >> 1;
    return (count == stringLen)? kSCLError_NoErr : kSCLError_BadParams;

}


static void createKeyJson(SCloudContextRef ctx, json& j)
{
    char                tempBuf[1024];
    size_t              tempLen;

    j[kVersionStr] = kSCloudMinProtocolVersion;
    j[kCurrentVersionStr] = kSCloudCurrentProtocolVersion;
    j[kKeySuiteStr] = ctx->key.keySuite;

    // Convert the symmetric key and the initial IV and store it
    bin2hex(ctx->key.symKey, ctx->key.symKeyLen + ctx->key.blockLength, tempBuf, &tempLen);
    tempBuf[tempLen] = '\0';
    j[kSymKeyStr] = tempBuf;

    b64Encode(ctx->key.hash, SKEIN256_DIGEST_LENGTH, tempBuf, SKEIN256_DIGEST_LENGTH*2);
    j[kHashStr] = tempBuf;
}

SCLError SCloudEncryptGetKeyBLOB(SCloudContextRef ctx, uint8_t **outData, size_t *outSize)
{
    SCLError            err = kSCLError_NoErr;
    uint8_t             *outBuf = nullptr;

    json jsn;

    createKeyJson(ctx, jsn);

    auto jsonString = jsn.dump();
    outBuf = static_cast<uint8_t*>(malloc(jsonString.size() + 1));
    memcpy(outBuf, jsonString.c_str(), jsonString.size() + 1);
    *outData = outBuf;
    *outSize = jsonString.size();

    return err;
}

SCLError SCloudEncryptGetSegmentBLOB(SCloudContextRef ctx, int segNum, uint8_t **outData, size_t *outSize) {

    SCLError            err = kSCLError_NoErr;
    uint8_t             *outBuf = nullptr;
    char                tempBuf[1024];
    size_t              tempLen;

    json itemArray = json::array();
    itemArray += segNum;

    URL64_encode(ctx->locator, TRUNCATED_LOCATOR_BITS >>3,  (uint8_t*)tempBuf, &tempLen);
    tempBuf[tempLen] = '\0';
    itemArray += tempBuf;

    json key;
    createKeyJson(ctx, key);
    itemArray += key;

    auto jsonString = itemArray.dump();
    outBuf = static_cast<uint8_t*>(XMALLOC(jsonString.size() + 1));
    memcpy(outBuf, jsonString.c_str(), jsonString.size() + 1);
    *outData = outBuf;
    *outSize = jsonString.size();

    return err;
}

