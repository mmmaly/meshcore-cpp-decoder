// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include <vector>
#include "../../types/payloads.h"
#include "../../types/packet.h"

namespace meshcore {

class AdvertPayloadDecoder {
public:
    static AdvertPayload decode(const uint8_t* payload, size_t len);
    static AdvertPayload decodeWithVerification(const uint8_t* payload, size_t len);

    static std::vector<PayloadSegment> generateSegments(const uint8_t* payload, size_t len, int segmentOffset = 0);

private:
    static DeviceRole parseDeviceRole(uint8_t flags);
    static uint32_t readUint32LE(const uint8_t* buf, size_t offset);
    static int32_t readInt32LE(const uint8_t* buf, size_t offset);
    static std::string sanitizeControlCharacters(const std::string& value);
};

} // namespace meshcore
