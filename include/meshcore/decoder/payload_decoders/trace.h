// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include "../../types/payloads.h"
#include "../../types/packet.h"

namespace meshcore {

class TracePayloadDecoder {
public:
    static TracePayload decode(const uint8_t* payload, size_t len,
                               const std::optional<std::vector<std::string>>& pathData = std::nullopt);
    static std::vector<PayloadSegment> generateSegments(const uint8_t* payload, size_t len, int segmentOffset = 0);

private:
    static uint32_t readUint32LE(const uint8_t* buf, size_t offset);
};

} // namespace meshcore
