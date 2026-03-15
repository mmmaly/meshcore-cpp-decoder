// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/anon_request.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

AnonRequestPayload AnonRequestPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    AnonRequestPayload anon;
    anon.type = PayloadType::AnonRequest;
    anon.version = PayloadVersion::Version1;

    if (len < 35) {
        anon.isValid = false;
        anon.errors.push_back("AnonRequest payload too short");
        return anon;
    }

    try {
        size_t offset = 0;

        anon.destinationHash = byteToHex(payload[offset]);
        offset += 1;

        anon.senderPublicKey = bytesToHex(payload + offset, 32);
        offset += 32;

        anon.cipherMac = bytesToHex(payload + offset, 2);
        offset += 2;

        anon.ciphertext = bytesToHex(payload + offset, len - offset);
        anon.ciphertextLength = len - 35;
        anon.isValid = true;
    } catch (const std::exception& e) {
        anon.isValid = false;
        anon.errors.push_back(e.what());
    }

    return anon;
}

std::vector<PayloadSegment> AnonRequestPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 35) {
        segments.push_back({"Invalid AnonRequest Data", "AnonRequest payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;
    segments.push_back({"Destination Hash", "First byte of destination node public key",
                        segmentOffset + offset, segmentOffset + offset, byteToHex(payload[offset])});
    offset += 1;

    segments.push_back({"Sender Public Key", "Ed25519 public key of sender (32 bytes)",
                        segmentOffset + offset, segmentOffset + offset + 31, bytesToHex(payload + offset, 32)});
    offset += 32;

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
