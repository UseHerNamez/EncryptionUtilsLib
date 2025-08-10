// EncryptionUtils.cpp
#include "EncryptionUtils.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <limits>   // for std::numeric_limits

// third party - only in the .cpp
#pragma warning(push, 0)
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#pragma warning(pop)

// OpenSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define _CRT_SECURE_NO_WARNINGS

// --- file helpers ---

std::string readKeyFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open key file: " << filename << std::endl;
        return {};
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string key = buffer.str();
    key.erase(std::remove(key.begin(), key.end(), '\r'), key.end());
    return key;
}

// --- token helpers ---

std::string GenerateToken(const std::unordered_map<std::string, std::string>& payloadClaims,
    std::chrono::seconds expiresIn)
{
    const std::string privateKey = readKeyFile("private.pem");
    const std::string publicKey = readKeyFile("public.pem");
    if (privateKey.empty() || publicKey.empty()) {
        std::cerr << "Keys could not be loaded.\n";
        return {};
    }

    try {
        const auto alg = jwt::algorithm::rs256(publicKey, privateKey, "", "");
        const auto now = std::chrono::system_clock::now();

        auto builder = jwt::create()
            .set_issuer(std::string(Authenticator))
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(now + expiresIn);

        for (const auto& kv : payloadClaims) {
            builder.set_payload_claim(kv.first, jwt::claim(kv.second));
        }
        return builder.sign(alg);
    }
    catch (const std::exception& e) {
        std::cerr << "JWT generation failed: " << e.what() << std::endl;
        return {};
    }
}

static TokenVerificationResult VerifyAndDecode(const std::string& token)
{
    const std::string publicKey = readKeyFile("public.pem");
    if (publicKey.empty()) {
        return { TokenStatus::Invalid, std::nullopt, "no_public_key" };
    }

    try {
        const auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(publicKey, "", "", ""))
            .with_issuer(std::string(Authenticator))
            .leeway(30); // seconds

        verifier.verify(decoded);

        TokenClaims c;
        if (decoded.has_payload_claim("userId"))   c.userId = decoded.get_payload_claim("userId").as_string();
        if (decoded.has_payload_claim("username")) c.username = decoded.get_payload_claim("username").as_string();
        if (decoded.has_payload_claim("charId"))   c.charId = decoded.get_payload_claim("charId").as_string();

        return { TokenStatus::Valid, TokenClaims{ std::move(c) }, {} };
    }
    catch (const std::exception& e) {
        const std::string msg = e.what();
        if (msg.find("expired") != std::string::npos) {
            return { TokenStatus::Expired, std::nullopt, "expired" };
        }
        return { TokenStatus::Invalid, std::nullopt, "verify_failed" };
    }
}

TokenVerificationResult validateAndExtractClaims(const std::string& token)
{
    return VerifyAndDecode(token);
}

// Convenience accessors from a token string
std::optional<std::string> getUserIdFromToken(const std::string& token) {
    auto r = VerifyAndDecode(token);
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->userId)
        : std::nullopt;
}
std::optional<std::string> getUsernameFromToken(const std::string& token) {
    auto r = VerifyAndDecode(token);
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->username)
        : std::nullopt;
}
std::optional<std::string> getCharIdFromToken(const std::string& token) {
    auto r = VerifyAndDecode(token);
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->charId)
        : std::nullopt;
}

// Convenience accessors from a pre-validated result
std::optional<std::string> getUserId(const TokenVerificationResult& r) {
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->userId)
        : std::nullopt;
}
std::optional<std::string> getUsername(const TokenVerificationResult& r) {
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->username)
        : std::nullopt;
}
std::optional<std::string> getCharId(const TokenVerificationResult& r) {
    return (r.status == TokenStatus::Valid && r.claims) ? std::optional<std::string>(r.claims->charId)
        : std::nullopt;
}

// --- OpenSSL helpers ---

static std::string getOpenSSLError() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf = nullptr;
    const long len = BIO_get_mem_data(bio, &buf);
    std::string ret;
    if (len > 0 && buf) ret.assign(buf, static_cast<size_t>(len));
    BIO_free(bio);
    return ret;
}

std::string encrypt(const std::string& plaintext, const std::string& key)
{
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "Failed to create cipher context.\n"; return {}; }

    if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        std::cerr << "Plaintext too large for OpenSSL.\n"; EVP_CIPHER_CTX_free(ctx); return {};
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()),
        reinterpret_cast<const unsigned char*>(IV.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx); std::cerr << "Failed to initialize encryption.\n"; return {};
    }

    const size_t cap = plaintext.size()
        + static_cast<size_t>(EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    std::string ciphertext(cap, '\0');

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&ciphertext[0]), &outLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx); std::cerr << "EncryptUpdate failed.\n"; return {};
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&ciphertext[outLen]), &finalLen) != 1) {
        std::cerr << "EncryptFinal failed: " << getOpenSSLError() << "\n";
        EVP_CIPHER_CTX_free(ctx); return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    const size_t total = static_cast<size_t>(outLen) + static_cast<size_t>(finalLen);
    ciphertext.resize(total);
    return ciphertext;
}


std::string decrypt(const std::string& ciphertext, const std::string& key)
{
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "Failed to create cipher context.\n"; return {}; }

    if (ciphertext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        std::cerr << "Ciphertext too large for OpenSSL.\n"; EVP_CIPHER_CTX_free(ctx); return {};
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()),
        reinterpret_cast<const unsigned char*>(IV.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx); std::cerr << "Failed to initialize decryption.\n"; return {};
    }

    const size_t cap = ciphertext.size()
        + static_cast<size_t>(EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    std::string plain(cap, '\0');

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&plain[0]), &outLen,
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx); std::cerr << "DecryptUpdate failed.\n"; return {};
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&plain[outLen]), &finalLen) != 1) {
        const auto e = getOpenSSLError();
        EVP_CIPHER_CTX_free(ctx); std::cerr << "DecryptFinal failed: " << e << "\n"; return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    const size_t total = static_cast<size_t>(outLen) + static_cast<size_t>(finalLen);
    plain.resize(total);
    return plain;
}

std::string HashPassword(const std::string& password)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, password.data(), password.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    const size_t len = static_cast<size_t>(out_len);

    static const char* lut = "0123456789abcdef";
    std::string hex;
    hex.resize(len * static_cast<size_t>(2));

    for (size_t i = 0; i < len; ++i) {
        const unsigned char b = digest[i];
        const size_t idx = i * static_cast<size_t>(2);
        hex[idx] = lut[b >> 4];
        hex[idx + 1] = lut[b & 0x0F];
    }
    return hex;
}