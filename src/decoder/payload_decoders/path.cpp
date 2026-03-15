// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/path.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

PathPayload PathPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    PathPayload path;
    path.type = PayloadType::Path;
    path.version = PayloadVersion::Version1;

    if (len < 2) {
        path.isValid = false;
        path.errors.push_back("Path payload too short");
        return path;
    }

    path.pathLength = payload[0];

    if (len < static_cast<size_t>(1 + path.pathLength + 1)) {
        path.isValid = false;
        path.errors.push_back("Path payload too short for path data");
        return path;
    }

    for (uint8_t i = 0; i < path.pathLength; i++) {
        path.pathHashes.push_back(byteToHex(payload[1 + i]));
    }

    path.extraType = payload[1 + path.pathLength];

    if (len > static_cast<size_t>(1 + path.pathLength + 1)) {
        path.extraData = bytesToHex(payload + 1 + path.pathLength + 1,
                                    len - 1 - path.pathLength - 1);
    }

    path.isValid = true;
    return path;
}

} // namespace meshcore
