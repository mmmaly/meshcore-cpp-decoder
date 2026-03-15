// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/response.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

ResponsePayload ResponsePayloadDecoder::decode(const uint8_t* payload, size_t len) {
    ResponsePayload response;
    response.type = PayloadType::Response;
    response.version = PayloadVersion::Version1;

    if (len < 4) {
        response.isValid = false;
        response.errors.push_back("Response payload too short");
        return response;
    }

    try {
        size_t offset = 0;

        response.destinationHash = byteToHex(payload[offset]);
        offset += 1;

        response.sourceHash = byteToHex(payload[offset]);
        offset += 1;

        response.cipherMac = bytesToHex(payload + offset, 2);
        offset += 2;

        response.ciphertext = bytesToHex(payload + offset, len - offset);
        response.ciphertextLength = len - 4;
        response.isValid = true;
    } catch (const std::exception& e) {
        response.isValid = false;
        response.errors.push_back(e.what());
    }

    return response;
}

std::vector<PayloadSegment> ResponsePayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 4) {
        segments.push_back({"Invalid Response Data", "Response payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;
    segments.push_back({"Destination Hash", "First byte of destination node public key",
                        segmentOffset + offset, segmentOffset + offset, byteToHex(payload[offset])});
    offset += 1;

    segments.push_back({"Source Hash", "First byte of source node public key",
                        segmentOffset + offset, segmentOffset + offset, byteToHex(payload[offset])});
    offset += 1;

    segments.push_back({"Cipher MAC", "MAC for encrypted data",
                        segmentOffset + offset, segmentOffset + offset + 1, bytesToHex(payload + offset, 2)});
    offset += 2;

    if (len > static_cast<size_t>(offset)) {
        segments.push_back({"Ciphertext", "Encrypted response data",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
