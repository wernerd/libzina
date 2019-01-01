//
// Created by werner on 07.06.16.
//

#ifndef LIBZINALOTL_UTILITIES_H
#define LIBZINALOTL_UTILITIES_H

/**
 * @file Utilities.h
 * @brief Some utility and helper functions
 * @ingroup Zina
 * @{
 */


#include <sys/types.h>
#include <string>
#include <vector>
#include <memory>
#include <cstring>

namespace zina {
    class Utilities {

    public:


        /**
         * @brief Splits a string around matches of the given delimiter character.
         *
         * Trailing empty strings are not included in the resulting array.
         * This function works similar to the Java string split function, however it does
         * not support regular expressions, only a simple delimiter character.
         *
         * @param data The std::string to split
         * @param delimiter The delimiter character
         * @return A vector of strings
         */
        static std::shared_ptr<std::vector<std::string> > splitString(const std::string& data, const std::string& delimiter);

        /**
         * @brief Returns a string with date and Time with milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17.122Z
         *
         * @return A formatted string with current Zulu time.
         */
        static std::string currentTimeMsISO8601();

        /**
         * @brief Returns a string with date and Time without milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17Z
         *
         * @return A formatted string with current Zulu time.
         */
        static std::string currentTimeISO8601();

        /**
         * @brief get the current time in milliseconds.
         *
         * @return The time in milliseconds
         */
        static uint64_t currentTimeMillis();

        /**
         * @brief Wipe a string.
         *
         * Fills the internal buffer of a string with zeros.
         *
         * @param toWipe The string to wipe.
         */
        static void wipeString(std::string &toWipe);

        /**
         * @brief Wipe memory.
         *
         * Fills a data buffer with zeros.
         *
         * @param data pointer to the data buffer.
         * @param length length of the data buffer in bytes
         */
        static inline void wipeMemory(void* data, size_t length) {
            static void * (*volatile memset_volatile)(void *, int, size_t) = std::memset;
            memset_volatile(data, 0, length);
        }

        /**
         * @brief URL-encode the input string and return the encoded string
         *
         * @param s Input string
         * @return URL-encoded string
         */
        static std::string urlEncode(std::string s);

        // Small functions to dump binary data as readable hex values, debugging for hases, encrypted data, etc
        static std::string hexdump(const char* title, const unsigned char *s, size_t l);

        static std::string hexdump(const std::string& title, const std::string& in) {
                return hexdump(title.c_str(), (uint8_t*)in.data(), in.size());
        }
    };
}

/**
 * @}
 */
#endif //LIBZINALOTL_UTILITIES_H
