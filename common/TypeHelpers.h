//
// Created by werner on 28.01.18.
//

#ifndef SZINA_TYPEHELPERS_H
#define SZINA_TYPEHELPERS_H

/**
 * @file TypeHelpers.h
 * @brief 
 * @ingroup 
 * @{
 */
#include <string>

#import "../json/json.hpp"

typedef std::unique_ptr<std::string> StringUnique;

/** Unique pointer to a Json data structure */
typedef std::unique_ptr<nlohmann::json> JSONUnique;

/**
 * @}
 */
#endif //SZINA_TYPEHELPERS_H
