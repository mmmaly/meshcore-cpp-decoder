// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <optional>
#include <nlohmann/json.hpp>

namespace meshcore {

struct AuthTokenPayload {
    std::string publicKey;
    int64_t iat = 0;
    std::optional<int64_t> exp;
    nlohmann::json extraClaims;
};

struct AuthToken {
    std::string header;
    std::string payload;
    std::string signature;
};

std::string createAuthToken(
    const AuthTokenPayload& payload,
    const std::string& privateKeyHex,
    const std::string& publicKeyHex
);

std::optional<AuthTokenPayload> verifyAuthToken(
    const std::string& token,
    const std::string& expectedPublicKeyHex = ""
);

std::optional<AuthToken> parseAuthToken(const std::string& token);
std::optional<AuthTokenPayload> decodeAuthTokenPayload(const std::string& token);

} // namespace meshcore
