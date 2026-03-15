// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/request.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

RequestPayload RequestPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    RequestPayload request;
    request.type = PayloadType::Request;
    request.version = PayloadVersion::Version1;

    if (len < 4) {
        request.isValid = false;
        request.errors.push_back("Request payload too short");
        return request;
    }

    try {
        size_t offset = 0;

        request.destinationHash = bytesToHex(payload + offset, 1);
        offset += 1;

        request.sourceHash = bytesToHex(payload + offset, 1);
        offset += 1;

        request.cipherMac = bytesToHex(payload + offset, 2);
        offset += 2;

        request.ciphertext = bytesToHex(payload + offset, len - offset);
        request.isValid = true;
    } catch (const std::exception& e) {
        request.isValid = false;
        request.errors.push_back(e.what());
    }

    return request;
}

std::vector<PayloadSegment> RequestPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 4) {
        segments.push_back({"Invalid Request Data", "Request payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;

    segments.push_back({"Destination Hash", "First byte of destination node public key",
                        segmentOffset + offset, segmentOffset + offset,
                        bytesToHex(payload + offset, 1)});
    offset += 1;

    segments.push_back({"Source Hash", "First byte of source node public key",
                        segmentOffset + offset, segmentOffset + offset,
                        bytesToHex(payload + offset, 1)});
    offset += 1;

    segments.push_back({"Cipher MAC", "MAC for encrypted data",
                        segmentOffset + offset, segmentOffset + offset + 1,
                        bytesToHex(payload + offset, 2)});
    offset += 2;

    if (len > static_cast<size_t>(offset)) {
        segments.push_back({"Ciphertext", "Encrypted message data",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
