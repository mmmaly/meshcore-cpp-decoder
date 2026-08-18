// Copyright (c) 2026
// MIT License
//
// The encoding counterpart of MeshCorePacketDecoder: builds the raw bytes a
// node transmits. Every builder is the exact inverse of the corresponding
// decoder in this library, and the round-trip is covered by tests, so the two
// directions cannot drift apart.

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "meshcore/types/enums.h"

namespace meshcore {

struct EncodeResult {
    bool success = false;
    std::vector<uint8_t> bytes;
    std::string error;
};

class MeshCorePacketEncoder {
public:
    // Assemble a complete packet: header byte, optional transport codes,
    // path-length byte (hash count in bits 0-5, hash size - 1 in bits 6-7),
    // path hashes, payload.
    static EncodeResult buildPacket(
        RouteType routeType,
        PayloadType payloadType,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& path = {},
        uint8_t pathHashSize = 1,
        std::optional<std::pair<uint16_t, uint16_t>> transportCodes = std::nullopt,
        PayloadVersion version = PayloadVersion::Version1
    );

    // GroupText payload: channel_hash(1) + cipher_mac(2) + ciphertext.
    // Plaintext is timestamp(4 LE) + flags(1) + "sender: message", zero-padded
    // to the AES block, encrypted AES-128-ECB with the 16-byte channel key;
    // MAC is the first two bytes of HMAC-SHA256 over the ciphertext keyed
    // with the 32-byte channel secret (key + 16 zero bytes).
    static EncodeResult buildGroupTextPayload(
        const std::string& channelKeyHex,
        const std::string& sender,
        const std::string& message,
        uint32_t timestamp,
        uint8_t flags = 0
    );

    // Advert payload: public_key(32) + timestamp(4 LE) + signature(64) +
    // flags(1) [+ lat(4 LE)+lon(4 LE)] [+ name]. The signature is Ed25519
    // over public_key + timestamp + app_data (flags onward).
    static EncodeResult buildAdvertPayload(
        const std::string& privateKeyHex,
        const std::string& publicKeyHex,
        uint32_t timestamp,
        const std::string& name,
        DeviceRole role = DeviceRole::ChatNode,
        std::optional<std::pair<double, double>> latLon = std::nullopt
    );
};

} // namespace meshcore
