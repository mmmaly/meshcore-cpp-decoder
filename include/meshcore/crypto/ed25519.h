// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace meshcore {

class Ed25519 {
public:
    static bool verifyAdvertisementSignature(
        const std::string& publicKeyHex,
        const std::string& signatureHex,
        uint32_t timestamp,
        const std::string& appDataHex
    );

    static std::string derivePublicKey(const std::string& privateKeyHex);
    static bool validateKeyPair(const std::string& privateKeyHex, const std::string& expectedPublicKeyHex);

    static std::string sign(
        const std::string& messageHex,
        const std::string& privateKeyHex,
        const std::string& publicKeyHex
    );

    static bool verify(
        const std::string& signatureHex,
        const std::string& messageHex,
        const std::string& publicKeyHex
    );

private:
    static std::vector<uint8_t> constructAdvertSignedMessage(
        const std::string& publicKeyHex,
        uint32_t timestamp,
        const std::vector<uint8_t>& appData
    );
};

} // namespace meshcore
