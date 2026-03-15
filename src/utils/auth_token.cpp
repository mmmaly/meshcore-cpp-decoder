// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/utils/auth_token.h"
#include "meshcore/utils/base64.h"
#include "meshcore/utils/hex.h"
#include "meshcore/crypto/ed25519.h"
#include <chrono>
#include <sstream>
#include <algorithm>

namespace meshcore {

std::string createAuthToken(
    const AuthTokenPayload& payload,
    const std::string& privateKeyHex,
    const std::string& publicKeyHex
) {
    // Create header
    nlohmann::json header;
    header["alg"] = "Ed25519";
    header["typ"] = "JWT";

    // Create payload JSON
    nlohmann::json payloadJson;
    std::string pubKey = payload.publicKey.empty() ? publicKeyHex : payload.publicKey;
    std::transform(pubKey.begin(), pubKey.end(), pubKey.begin(), ::toupper);
    payloadJson["publicKey"] = pubKey;

    int64_t iat = payload.iat;
    if (iat == 0) {
        iat = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    payloadJson["iat"] = iat;

    if (payload.exp.has_value()) {
        payloadJson["exp"] = payload.exp.value();
    }

    // Merge extra claims
    if (!payload.extraClaims.is_null() && payload.extraClaims.is_object()) {
        for (auto& [key, value] : payload.extraClaims.items()) {
            payloadJson[key] = value;
        }
    }

    // Encode header and payload
    std::string headerEncoded = base64urlEncode(header.dump());
    std::string payloadEncoded = base64urlEncode(payloadJson.dump());

    // Create signing input
    std::string signingInput = headerEncoded + "." + payloadEncoded;
    std::string signingInputHex = bytesToHex(
        std::vector<uint8_t>(signingInput.begin(), signingInput.end())
    );

    // Sign
    std::string signatureHex = Ed25519::sign(signingInputHex, privateKeyHex, pubKey);

    return headerEncoded + "." + payloadEncoded + "." + signatureHex;
}

std::optional<AuthTokenPayload> verifyAuthToken(
    const std::string& token,
    const std::string& expectedPublicKeyHex
) {
    try {
        // Parse token parts
        size_t dot1 = token.find('.');
        if (dot1 == std::string::npos) return std::nullopt;
        size_t dot2 = token.find('.', dot1 + 1);
        if (dot2 == std::string::npos) return std::nullopt;
        if (token.find('.', dot2 + 1) != std::string::npos) return std::nullopt;

        std::string headerEncoded = token.substr(0, dot1);
        std::string payloadEncoded = token.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string signatureHex = token.substr(dot2 + 1);

        // Decode header
        auto headerBytes = base64urlDecode(headerEncoded);
        std::string headerJson(headerBytes.begin(), headerBytes.end());
        auto header = nlohmann::json::parse(headerJson);

        if (header["alg"] != "Ed25519" || header["typ"] != "JWT") {
            return std::nullopt;
        }

        // Decode payload
        auto payloadBytes = base64urlDecode(payloadEncoded);
        std::string payloadJson(payloadBytes.begin(), payloadBytes.end());
        auto payloadObj = nlohmann::json::parse(payloadJson);

        if (!payloadObj.contains("publicKey") || !payloadObj.contains("iat")) {
            return std::nullopt;
        }

        AuthTokenPayload result;
        result.publicKey = payloadObj["publicKey"].get<std::string>();
        result.iat = payloadObj["iat"].get<int64_t>();

        if (payloadObj.contains("exp")) {
            result.exp = payloadObj["exp"].get<int64_t>();
        }

        // Check public key match
        if (!expectedPublicKeyHex.empty()) {
            std::string a = result.publicKey, b = expectedPublicKeyHex;
            std::transform(a.begin(), a.end(), a.begin(), ::toupper);
            std::transform(b.begin(), b.end(), b.begin(), ::toupper);
            if (a != b) return std::nullopt;
        }

        // Check expiration
        if (result.exp.has_value()) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            if (now > result.exp.value()) return std::nullopt;
        }

        // Verify signature
        std::string signingInput = headerEncoded + "." + payloadEncoded;
        std::string signingInputHex = bytesToHex(
            std::vector<uint8_t>(signingInput.begin(), signingInput.end())
        );

        if (!Ed25519::verify(signatureHex, signingInputHex, result.publicKey)) {
            return std::nullopt;
        }

        // Collect extra claims
        for (auto& [key, value] : payloadObj.items()) {
            if (key != "publicKey" && key != "iat" && key != "exp") {
                result.extraClaims[key] = value;
            }
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<AuthToken> parseAuthToken(const std::string& token) {
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return std::nullopt;
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return std::nullopt;

    AuthToken result;
    result.header = token.substr(0, dot1);
    result.payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
    result.signature = token.substr(dot2 + 1);
    return result;
}

std::optional<AuthTokenPayload> decodeAuthTokenPayload(const std::string& token) {
    try {
        size_t dot1 = token.find('.');
        if (dot1 == std::string::npos) return std::nullopt;
        size_t dot2 = token.find('.', dot1 + 1);
        if (dot2 == std::string::npos) return std::nullopt;

        std::string payloadEncoded = token.substr(dot1 + 1, dot2 - dot1 - 1);
        auto payloadBytes = base64urlDecode(payloadEncoded);
        std::string payloadJson(payloadBytes.begin(), payloadBytes.end());
        auto payloadObj = nlohmann::json::parse(payloadJson);

        AuthTokenPayload result;
        result.publicKey = payloadObj.value("publicKey", "");
        result.iat = payloadObj.value("iat", int64_t(0));
        if (payloadObj.contains("exp")) {
            result.exp = payloadObj["exp"].get<int64_t>();
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace meshcore
