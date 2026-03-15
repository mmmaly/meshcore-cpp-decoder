// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <optional>
#include <cstdint>

namespace meshcore {

struct DecryptionResult {
    bool success = false;
    uint32_t timestamp = 0;
    uint8_t flags = 0;
    std::optional<std::string> sender;
    std::string message;
    std::string error;
};

class ChannelCrypto {
public:
    static DecryptionResult decryptGroupTextMessage(
        const std::string& ciphertext,
        const std::string& cipherMac,
        const std::string& channelKey
    );

    static std::string calculateChannelHash(const std::string& secretKeyHex);
};

} // namespace meshcore
