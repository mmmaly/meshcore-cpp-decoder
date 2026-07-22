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

    // path_len byte: bits 0-5 = hash count, bits 6-7 = hash size - 1
    uint8_t pathLenByte = payload[0];
    uint8_t hashSize = (pathLenByte >> 6) + 1;
    path.pathLength = pathLenByte & 63;
    size_t pathBytes = static_cast<size_t>(path.pathLength) * hashSize;

    if (len < pathBytes + 2) {
        path.isValid = false;
        path.errors.push_back("Path payload too short for path data");
        return path;
    }

    for (uint8_t i = 0; i < path.pathLength; i++) {
        path.pathHashes.push_back(bytesToHex(payload + 1 + i * hashSize, hashSize));
    }

    path.extraType = payload[1 + pathBytes];

    if (len > pathBytes + 2) {
        path.extraData = bytesToHex(payload + 1 + pathBytes + 1,
                                    len - 1 - pathBytes - 1);
    }

    path.isValid = true;
    return path;
}

} // namespace meshcore
