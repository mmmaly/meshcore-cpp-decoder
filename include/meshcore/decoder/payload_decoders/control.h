// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include <vector>
#include <variant>
#include "../../types/payloads.h"
#include "../../types/packet.h"

namespace meshcore {

class ControlPayloadDecoder {
public:
    using Result = std::variant<ControlDiscoverReqPayload, ControlDiscoverRespPayload>;

    static Result decode(const uint8_t* payload, size_t len);
    static std::vector<PayloadSegment> generateSegments(const uint8_t* payload, size_t len, int segmentOffset = 0);

private:
    static ControlDiscoverReqPayload decodeDiscoverReq(const uint8_t* payload, size_t len);
    static ControlDiscoverRespPayload decodeDiscoverResp(const uint8_t* payload, size_t len);
    static std::vector<std::string> parseTypeFilter(uint8_t filter);
    static uint32_t readUint32LE(const uint8_t* buf, size_t offset);
};

} // namespace meshcore
