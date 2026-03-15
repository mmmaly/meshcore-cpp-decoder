// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/ack.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

AckPayload AckPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    AckPayload ack;
    ack.type = PayloadType::Ack;
    ack.version = PayloadVersion::Version1;

    if (len < 4) {
        ack.isValid = false;
        ack.errors.push_back("Ack payload too short");
        return ack;
    }

    ack.checksum = bytesToHex(payload, 4);
    ack.isValid = true;
    return ack;
}

std::vector<PayloadSegment> AckPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 4) {
        segments.push_back({"Invalid Ack Data", "Ack payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    segments.push_back({"Checksum", "CRC checksum: 0x" + bytesToHex(payload, 4),
                        segmentOffset, segmentOffset + 3, bytesToHex(payload, 4)});

    if (len > 4) {
        segments.push_back({"Additional Data", "Extra data in Ack payload",
                            segmentOffset + 4, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + 4, len - 4)});
    }

    return segments;
}

} // namespace meshcore
