// EncryptionUtils.h
#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <chrono>
#include <optional>

// Encryption
std::string encrypt(const std::string& plaintext, const std::string& key);
std::string decrypt(const std::string& ciphertext, const std::string& key);

// Token model
enum class TokenStatus { Valid, Expired, Invalid };

struct TokenClaims {
    std::string userId;
    std::string username;
    std::string charId;
};

struct TokenVerificationResult {
    TokenStatus status{ TokenStatus::Invalid };
    std::optional<TokenClaims> claims; // present only when status == Valid
    std::string reason;                // optional context for logs
};

// Token API
std::string GenerateToken(const std::unordered_map<std::string, std::string>& payloadClaims,
    std::chrono::seconds expiresIn = std::chrono::hours(24));

// Validate and return claims if ok
TokenVerificationResult validateAndExtractClaims(const std::string& token);

// Convenience - extract a single field directly from a token string
std::optional<std::string> getUserIdFromToken(const std::string& token);
std::optional<std::string> getUsernameFromToken(const std::string& token);
std::optional<std::string> getCharIdFromToken(const std::string& token);

// Same helpers from a pre-validated result - avoids re-decoding
std::optional<std::string> getUserId(const TokenVerificationResult& r);
std::optional<std::string> getUsername(const TokenVerificationResult& r);
std::optional<std::string> getCharId(const TokenVerificationResult& r);

std::string HashPassword(const std::string& password);

// Constants - header safe
inline constexpr std::string_view IV = "0123456789ABCDEF";
inline constexpr std::string_view Authenticator = "ComputerSaviourLoginSrv";

// Read PEM key - kept public since you already use it from multiple places
std::string readKeyFile(const std::string& path);
