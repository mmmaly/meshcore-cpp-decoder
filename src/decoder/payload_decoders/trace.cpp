// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/trace.h"
#include "meshcore/utils/hex.h"
#include <sstream>

namespace meshcore {

uint32_t TracePayloadDecoder::readUint32LE(const uint8_t* buf, size_t offset) {
    return static_cast<uint32_t>(buf[offset]) |
           (static_cast<uint32_t>(buf[offset + 1]) << 8) |
           (static_cast<uint32_t>(buf[offset + 2]) << 16) |
           (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

TracePayload TracePayloadDecoder::decode(const uint8_t* payload, size_t len,
                                          const std::optional<std::vector<std::string>>& pathData) {
    TracePayload trace;
    trace.type = PayloadType::Trace;
    trace.version = PayloadVersion::Version1;
    trace.traceTag = "00000000";

    if (len < 9) {
        trace.isValid = false;
        trace.errors.push_back("Trace payload too short (need at least tag(4) + auth(4) + flags(1))");
        return trace;
    }

    try {
        size_t offset = 0;

        uint32_t traceTagRaw = readUint32LE(payload, offset);
        trace.traceTag = numberToHex(traceTagRaw, 8);
        offset += 4;

        trace.authCode = readUint32LE(payload, offset);
        offset += 4;

        trace.flags = payload[offset];
        offset += 1;

        while (offset < len) {
            trace.pathHashes.push_back(byteToHex(payload[offset]));
            offset++;
        }

        // Extract SNR values from path data
        if (pathData.has_value() && !pathData->empty()) {
            std::vector<double> snrVals;
            for (const auto& hexByte : *pathData) {
                uint8_t byteValue = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
                int8_t snrSigned = byteValue > 127 ? static_cast<int8_t>(byteValue - 256) : static_cast<int8_t>(byteValue);
                snrVals.push_back(snrSigned / 4.0);
            }
            trace.snrValues = snrVals;
        }

        trace.isValid = true;
    } catch (const std::exception& e) {
        trace.isValid = false;
        trace.errors.push_back(e.what());
    }

    return trace;
}

std::vector<PayloadSegment> TracePayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 9) {
        segments.push_back({"Invalid Trace Data", "Trace payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;

    uint32_t tag = readUint32LE(payload, offset);
    std::ostringstream tagDesc;
    tagDesc << "Unique identifier: 0x" << std::hex << tag;
    segments.push_back({"Trace Tag", tagDesc.str(),
                        segmentOffset + offset, segmentOffset + offset + 3,
                        bytesToHex(payload + offset, 4)});
    offset += 4;

    uint32_t auth = readUint32LE(payload, offset);
    segments.push_back({"Auth Code", "Authentication code: " + std::to_string(auth),
                        segmentOffset + offset, segmentOffset + offset + 3,
                        bytesToHex(payload + offset, 4)});
    offset += 4;

    uint8_t flags = payload[offset];
    std::ostringstream flagsDesc;
    flagsDesc << "Flags: 0x" << std::hex << static_cast<int>(flags);
    segments.push_back({"Flags", flagsDesc.str(),
                        segmentOffset + offset, segmentOffset + offset,
                        byteToHex(flags)});
    offset += 1;

    if (offset < static_cast<int>(len)) {
        segments.push_back({"Path Hashes", "Node hashes in trace path",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
