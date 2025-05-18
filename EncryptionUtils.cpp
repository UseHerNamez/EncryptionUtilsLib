#include "pch.h"
#include "include\UtilsStaticLib\EncryptionUtils.h"

#define _CRT_SECURE_NO_WARNINGS

std::string readKeyFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open key file: " << filename << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string key = buffer.str();
    key.erase(std::remove(key.begin(), key.end(), '\r'), key.end());
    return key;
}

std::string GenerateToken(const std::unordered_map<std::string, std::string>& payloadClaims,
    std::chrono::seconds expiresIn)
{
    std::string privateKey = readKeyFile("private.pem");
    std::string publicKey = readKeyFile("public.pem");

    if (privateKey.empty() || publicKey.empty()) {
        std::cerr << "Keys could not be loaded.\n";
        return "";
    }

    try {
        auto alg = jwt::algorithm::rs256(publicKey, privateKey, "", "");
        auto now = std::chrono::system_clock::now();

        auto tokenBuilder = jwt::create()
            .set_issuer(Authenticator)
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(now + expiresIn);

        // Add all dynamic claims
        for (const std::pair<const std::string, std::string>& pair : payloadClaims) {
            tokenBuilder.set_payload_claim(pair.first, jwt::claim(pair.second));
        }

        return tokenBuilder.sign(alg);
    }
    catch (const std::exception& e) {
        std::cerr << "JWT generation failed: " << e.what() << std::endl;
        return "";
    }
}

std::string getUserIdFromToken(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded) {
    if (decoded.has_payload_claim("userId")) {
        return decoded.get_payload_claim("userId").as_string();
    }
    return "";
}

std::string getUsernameFromToken(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded) {
    if (decoded.has_payload_claim("username")) {
        return decoded.get_payload_claim("username").as_string();
    }
    return "";
}

TokenVerificationResult validateAndExtractClaims(const std::string& token) {
    std::string publicKey = readKeyFile("public.pem");
    if (publicKey.empty()) {
        std::cerr << "Failed to read public key." << std::endl;
        return { TokenStatus::Invalid, boost::none };  // Public key error
    }
    try {
        // Decode the token without verification to inspect the claims
        auto decoded = jwt::decode(token);
        // Verify the token (signature, issuer, expiration, etc.)
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(publicKey, "", "", ""))
            .with_issuer(Authenticator)
            .leeway(30);

        // Verify the decoded token
        verifier.verify(decoded);

        // Token is valid, return the decoded JWT
        return { TokenStatus::Valid, decoded };
    }
    catch (const std::exception& e) {  // Catch general C++ exception
        std::cout << "Token verification failed: " << e.what() << std::endl;

        // Check if the exception is related to expiration
        if (std::string(e.what()).find("token is expired") != std::string::npos) {
            std::cerr << "Token has expired." << std::endl;
            return { TokenStatus::Expired, boost::none };
        }

        // If the error is generic verification failure (invalid token, wrong issuer, etc.)
        return { TokenStatus::Invalid, boost::none };
    }
}

std::string encrypt(const std::string& plaintext, const std::string& key)
{
    OpenSSL_add_all_algorithms();

    // Set up the cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create cipher context." << std::endl;
        return "";
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(IV.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to initialize encryption operation." << std::endl;
        return "";
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int ciphertextLength = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &ciphertextLength, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to perform encryption update." << std::endl;
        return "";
    }

    // Finalize the encryption
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[ciphertextLength]), &finalLength) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to finalize encryption." << std::endl;
        return "";
    }

    ciphertextLength += finalLength;
    EVP_CIPHER_CTX_free(ctx);

    // Resize the ciphertext to the actual length
    ciphertext.resize(ciphertextLength);

    return ciphertext;
}

// Convert OpenSSL error codes to human-readable string
std::string getOpenSSLError() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

std::string decrypt(const std::string& ciphertext, const std::string& key)
{
    OpenSSL_add_all_algorithms();

    // Set up the cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create cipher context." << std::endl;
        return "";
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(IV.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to initialize decryption operation." << std::endl;
        return "";
    }

    // Provide the message to be decrypted, and obtain the decrypted output
    std::string decryptedtext;
    decryptedtext.resize(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int decryptedLength = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decryptedtext[0]), &decryptedLength, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to perform decryption update." << std::endl;
        return "";
    }

    // Finalize the decryption
    int finalLength = 0;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decryptedtext[decryptedLength]), &finalLength) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "Failed to finalize decryption: " << getOpenSSLError() << std::endl;
        return "";
    }

    decryptedLength += finalLength;
    EVP_CIPHER_CTX_free(ctx);

    // Resize the decrypted text to the actual length
    decryptedtext.resize(decryptedLength);

    return decryptedtext;
}