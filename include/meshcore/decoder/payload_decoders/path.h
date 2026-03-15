// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>
#include "../../types/payloads.h"

namespace meshcore {

class PathPayloadDecoder {
public:
    static PathPayload decode(const uint8_t* payload, size_t len);
};

} // namespace meshcore
