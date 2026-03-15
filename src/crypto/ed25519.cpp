// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/crypto/ed25519.h"
#include "meshcore/utils/hex.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace meshcore {

bool Ed25519::verifyAdvertisementSignature(
    const std::string& publicKeyHex,
    const std::string& signatureHex,
    uint32_t timestamp,
    const std::string& appDataHex
) {
    try {
        auto appData = hexToBytes(appDataHex);
        auto message = constructAdvertSignedMessage(publicKeyHex, timestamp, appData);
        auto messageHex = bytesToHex(message);
        return verify(signatureHex, messageHex, publicKeyHex);
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> Ed25519::constructAdvertSignedMessage(
    const std::string& publicKeyHex,
    uint32_t timestamp,
    const std::vector<uint8_t>& appData
) {
    auto publicKey = hexToBytes(publicKeyHex);

    // Timestamp (4 bytes, little-endian)
    uint8_t timestampBytes[4];
    timestampBytes[0] = timestamp & 0xFF;
    timestampBytes[1] = (timestamp >> 8) & 0xFF;
    timestampBytes[2] = (timestamp >> 16) & 0xFF;
    timestampBytes[3] = (timestamp >> 24) & 0xFF;

    // Concatenate: public_key + timestamp + app_data
    std::vector<uint8_t> message;
    message.reserve(32 + 4 + appData.size());
    message.insert(message.end(), publicKey.begin(), publicKey.end());
    message.insert(message.end(), timestampBytes, timestampBytes + 4);
    message.insert(message.end(), appData.begin(), appData.end());

    return message;
}

std::string Ed25519::derivePublicKey(const std::string& privateKeyHex) {
    auto privKeyBytes = hexToBytes(privateKeyHex);
    if (privKeyBytes.size() != 64) {
        throw std::runtime_error("Invalid private key length: expected 64 bytes");
    }

    // The orlp/ed25519 format stores a 64-byte private key where:
    // First 32 bytes = seed, Second 32 bytes = derived data
    // OpenSSL ED25519 expects a 32-byte seed
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                    privKeyBytes.data(), 32);
    if (!pkey) {
        throw std::runtime_error("Failed to create ED25519 key from seed");
    }

    uint8_t pubKey[32];
    size_t pubKeyLen = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pubKey, &pubKeyLen) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to derive public key");
    }
    EVP_PKEY_free(pkey);

    return bytesToHex(pubKey, 32);
}

bool Ed25519::validateKeyPair(const std::string& privateKeyHex, const std::string& expectedPublicKeyHex) {
    try {
        auto derived = derivePublicKey(privateKeyHex);
        // Case-insensitive compare
        std::string a = derived, b = expectedPublicKeyHex;
        std::transform(a.begin(), a.end(), a.begin(), ::toupper);
        std::transform(b.begin(), b.end(), b.begin(), ::toupper);
        return a == b;
    } catch (...) {
        return false;
    }
}

std::string Ed25519::sign(
    const std::string& messageHex,
    const std::string& privateKeyHex,
    const std::string& publicKeyHex
) {
    auto privKeyBytes = hexToBytes(privateKeyHex);
    auto messageBytes = hexToBytes(messageHex);

    if (privKeyBytes.size() != 64) {
        throw std::runtime_error("Invalid private key length: expected 64 bytes");
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                    privKeyBytes.data(), 32);
    if (!pkey) {
        throw std::runtime_error("Failed to create ED25519 key");
    }

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create MD context");
    }

    if (EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to init signing");
    }

    size_t sigLen = 64;
    uint8_t signature[64];
    if (EVP_DigestSign(mdCtx, signature, &sigLen,
                       messageBytes.data(), messageBytes.size()) != 1) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign message");
    }

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    return bytesToHex(signature, sigLen);
}

bool Ed25519::verify(
    const std::string& signatureHex,
    const std::string& messageHex,
    const std::string& publicKeyHex
) {
    try {
        auto sigBytes = hexToBytes(signatureHex);
        auto msgBytes = hexToBytes(messageHex);
        auto pubKeyBytes = hexToBytes(publicKeyHex);

        if (sigBytes.size() != 64 || pubKeyBytes.size() != 32) {
            return false;
        }

        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                       pubKeyBytes.data(), 32);
        if (!pkey) return false;

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
            EVP_PKEY_free(pkey);
            return false;
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
            EVP_MD_CTX_free(mdCtx);
            EVP_PKEY_free(pkey);
            return false;
        }

        int result = EVP_DigestVerify(mdCtx, sigBytes.data(), sigBytes.size(),
                                       msgBytes.data(), msgBytes.size());

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        return result == 1;
    } catch (...) {
        return false;
    }
}

} // namespace meshcore
