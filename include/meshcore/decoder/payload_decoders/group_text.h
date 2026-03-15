// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include <vector>
#include "../../types/payloads.h"
#include "../../types/packet.h"
#include "../../crypto/key_manager.h"

namespace meshcore {

class GroupTextPayloadDecoder {
public:
    static GroupTextPayload decode(const uint8_t* payload, size_t len,
                                   const MeshCoreKeyStore* keyStore = nullptr);
    static std::vector<PayloadSegment> generateSegments(const uint8_t* payload, size_t len, int segmentOffset = 0);
};

} // namespace meshcore
