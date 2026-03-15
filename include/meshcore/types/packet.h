// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <optional>
#include "payloads.h"

namespace meshcore {

struct HeaderField {
    std::string bits;
    std::string field;
    std::string value;
    std::string binary;
};

struct HeaderBreakdown {
    std::string fullBinary;
    std::vector<HeaderField> fields;
};

struct PacketSegment {
    std::string name;
    std::string description;
    int startByte = 0;
    int endByte = 0;
    std::string value;
    std::optional<HeaderBreakdown> headerBreakdown;
};

struct PayloadSegment {
    std::string name;
    std::string description;
    int startByte = 0;
    int endByte = 0;
    std::string value;
    std::optional<std::string> decryptedMessage;
};

struct DecodedPacket {
    std::string messageHash;
    RouteType routeType = RouteType::Flood;
    PayloadType payloadType = PayloadType::RawCustom;
    PayloadVersion payloadVersion = PayloadVersion::Version1;
    std::optional<std::pair<uint16_t, uint16_t>> transportCodes;
    uint8_t pathLength = 0;
    std::optional<std::vector<std::string>> path;
    std::string payloadRaw;
    std::optional<PayloadData> payloadDecoded;
    size_t totalBytes = 0;
    bool isValid = false;
    std::vector<std::string> errors;
};

struct PacketStructure {
    std::vector<PacketSegment> segments;
    size_t totalBytes = 0;
    std::string rawHex;
    std::string messageHash;
    struct {
        std::vector<PayloadSegment> segments;
        std::string hex;
        int startByte = 0;
        std::string type;
    } payload;
};

struct ValidationResult {
    bool isValid = false;
    std::vector<std::string> errors;
};

} // namespace meshcore
