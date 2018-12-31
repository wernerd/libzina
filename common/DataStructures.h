//
// Created by Werner Dittmann on 2018-12-28.
//

#ifndef LIBZINA_DATASTRUCTURES_H
#define LIBZINA_DATASTRUCTURES_H

#include "TypeHelpers.h"
#include "../ratchet/crypto/DhPublicKey.h"
#include "../ratchet/state/ZinaConversation.h"

/**
 * @file DataStructures.h
 * @brief The structures to handle common data.
 * @ingroup sZina
 * @{
 */

namespace zina {

    /**
     * @brief Key bundle data.
     *
     * The application fills in this structure after it got a new partner's key bundle from
     * a server which provides key bundles. The application parses the contents of the bundle
     * and fills in this data structure. The data in this structure is binary, not base64 encoded.
     *
     * The format of the key bundle depends on the server, thus the application needs to know
     * how to parse the data, for example based on the XEP-0384 (OMEMO) specification.
     */
    struct KeyBundle {
        PublicKeyUnique identityKey;        //!< The partner's long term identity key, mandatory
        PublicKeyUnique preKey;             //!< The partner's one-time pre-key, optional but strongly recommended
        PublicKeyUnique signedPreKey;       //!< The partner's signed pre-key, mandatory
        StringUnique signature;             //!< The signed pre-key's signature, mandatory
        int32_t preKeyId = 0;           //!< The numeric id of the one-time pre-key, or zero if one-time pre-key is not used
        int32_t signedPreKeyId = 0;     //!< The numeric id of the signed pre-key
    };
    typedef std::unique_ptr<KeyBundle> KeyBundleUnique;

    /**
     * @brief Data of generated one-time and signed pre-keys.
     *
     * The pre-key generator populates this data structure whe it generate and stores a new
     * one-time pre-key or new signed pre-key. In case it's a normal (one-time pre-key) then
     * #signature is empty.
     *
     * The function that generates and stores a batch of one-time pre-keys returns a list of
     * unique pointers to this data structure.
     */
    struct PreKeyData {
        PreKeyData(int32_t keyId, KeyPairUnique keyPair) : keyId(keyId), keyPair(move(keyPair)), signature(nullptr) {}

        int32_t keyId = 0;          //!< The random key id
        int32_t result = SUCCESS;   //!< Result code of the key generation, @c SUCCESS or error code
        bool isSigned = false;      //!< @c true if this is a signed pre-key
        time_t created = 0;         //!< Creation time of the pre-key
        KeyPairUnique keyPair;      //!< used when returning a generated pre key
        StringUnique signature;     //!< used when returning a signed pre key, empty otherwise
    };

    typedef std::unique_ptr<PreKeyData> PreKeyDataUnique;
    typedef std::unique_ptr<std::list<PreKeyDataUnique> > PreKeysListUnique;
}

/**
 * @}
 */
#endif //LIBZINA_DATASTRUCTURES_H
