// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/text_message.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

TextMessagePayload TextMessagePayloadDecoder::decode(const uint8_t* payload, size_t len) {
    TextMessagePayload msg;
    msg.type = PayloadType::TextMessage;
    msg.version = PayloadVersion::Version1;

    if (len < 4) {
        msg.isValid = false;
        msg.errors.push_back("TextMessage payload too short");
        return msg;
    }

    try {
        size_t offset = 0;

        msg.destinationHash = byteToHex(payload[offset]);
        offset += 1;

        msg.sourceHash = byteToHex(payload[offset]);
        offset += 1;

        msg.cipherMac = bytesToHex(payload + offset, 2);
        offset += 2;

        msg.ciphertext = bytesToHex(payload + offset, len - offset);
        msg.ciphertextLength = len - 4;
        msg.isValid = true;
    } catch (const std::exception& e) {
        msg.isValid = false;
        msg.errors.push_back(e.what());
    }

    return msg;
}

std::vector<PayloadSegment> TextMessagePayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 4) {
        segments.push_back({"Invalid TextMessage Data", "TextMessage payload too short",
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
        segments.push_back({"Ciphertext", "Encrypted message data",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
