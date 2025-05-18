#pragma once

#include <iostream>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <random>
#include <jwt-cpp/jwt.h>
#include "nlohmann/json.hpp"
#include <boost/optional.hpp> 

std::string encrypt(const std::string& plaintext, const std::string& key);
std::string decrypt(const std::string& ciphertext, const std::string& key);

//token

enum class TokenStatus {
    Valid,
    Expired,
    Invalid
};

struct TokenVerificationResult {
    TokenStatus status;
    boost::optional<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> decodedToken;
};

std::string GenerateToken(const std::unordered_map<std::string, std::string>& payloadClaims,
    std::chrono::seconds expiresIn = std::chrono::hours(24));

std::string getUserIdFromToken(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded);
std::string getUsernameFromToken(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded);
std::string readKeyFile(const std::string& path);
TokenVerificationResult validateAndExtractClaims(const std::string& token);

const std::string IV = "0123456789ABCDEF";
const std::string Authenticator = "ComputerSaviourLoginSrv";