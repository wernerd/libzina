//
// Created by Werner Dittmann on 2019-02-03.
//

#ifndef LIBZINA_USERDEVICESERVERAPI_H
#define LIBZINA_USERDEVICESERVERAPI_H
/**
 * @file
 * @brief Interface definition for key server functions
 * @ingroup
 * @{
 */

#include <cstdint>
#include <string>

#include "../keymanagment/KeyProvisioningServerApi.h"
#include "../ratchet/state/ZinaConversation.h"

namespace zina {

    /**
     * @brief Interface to server's functions to manage users devices.
     *
     * The ZINA key server should provide some functions to manage user devices.
     *
     * This class provides empty implementations which return a Generic error when called. A user and device server
     * interface class should inherit this class and provide a implementation. The user and device provisioning
     * functions callback to this class to update or retrieve key bundles.
     */
    class UserDeviceServerApi {
    public:

        /**
         * @brief Prepare this device for use.
         *
         * The server specific implementation of this functions should setup the device with the server. This
         * includes any steps to creates and initial set of pre-keys, signed pred-key (if supported) and other
         * information the server may need.
         *
         * The function exüects an initialized and ready to use local conversation that contains this client's
         * long term identity key pair, the user's id
         *
         * @param [in] conv  Initialized local conversation data
         * @param [in] deviceId Unique id of the device - unique withing user's account
         * @param [in] deviceName The device's name, may be empty if not known or not supported
         * @param [in] kpsApi class that implements the API to the key server
         * @param [in] store key and conversation store
         * @param [out] resultFromServer If the server returns additional data then the function stores it in this string, maybe empty on return
         * @return SUCCESS or an error code
         */
        virtual int32_t
        prepareDevice(const ZinaConversation& conv,
                      const std::string& deviceId,
                      const std::string& deviceName,
                      KeyProvisioningServerApi& kpsApi,
                      SQLiteStoreConv& store,
                      std::string& resultFromServer)
        {
            return GENERIC_ERROR;
        }

    };
}
/**
 * @}
 */

#endif //LIBZINA_USERDEVICESERVERAPI_H
