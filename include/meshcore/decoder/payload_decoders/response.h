// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include <vector>
#include "../../types/payloads.h"
#include "../../types/packet.h"

namespace meshcore {

class ResponsePayloadDecoder {
public:
    static ResponsePayload decode(const uint8_t* payload, size_t len);
    static std::vector<PayloadSegment> generateSegments(const uint8_t* payload, size_t len, int segmentOffset = 0);
};

} // namespace meshcore
