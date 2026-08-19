// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <optional>
#include <vector>
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

    // MAC-then-decrypt with a channel key, returning the raw plaintext
    // (GroupData and any future group payload need the bytes, not the
    // GroupText field parse).
    static std::optional<std::vector<uint8_t>> decryptRaw(
        const std::string& ciphertextHex, const std::string& cipherMacHex,
        const std::string& channelKeyHex);
};

} // namespace meshcore
