// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/packet_decoder.h"
#include "meshcore/utils/hex.h"
#include "meshcore/utils/enum_names.h"
#include "meshcore/decoder/payload_decoders/advert.h"
#include "meshcore/decoder/payload_decoders/trace.h"
#include "meshcore/decoder/payload_decoders/group_text.h"
#include "meshcore/decoder/payload_decoders/request.h"
#include "meshcore/decoder/payload_decoders/response.h"
#include "meshcore/decoder/payload_decoders/text_message.h"
#include "meshcore/decoder/payload_decoders/anon_request.h"
#include "meshcore/decoder/payload_decoders/ack.h"
#include "meshcore/decoder/payload_decoders/path.h"
#include "meshcore/decoder/payload_decoders/control.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace meshcore {

static uint32_t readUint32LE(const uint8_t* buf, size_t offset) {
    return static_cast<uint32_t>(buf[offset]) |
           (static_cast<uint32_t>(buf[offset + 1]) << 8) |
           (static_cast<uint32_t>(buf[offset + 2]) << 16) |
           (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

DecodedPacket MeshCorePacketDecoder::decode(const std::string& hexData,
                                            const MeshCoreKeyStore* keyStore) {
    DecodedPacket packet;

    std::vector<uint8_t> bytes;
    try {
        bytes = hexToBytes(hexData);
    } catch (const std::exception& e) {
        packet.errors.push_back(e.what());
        return packet;
    }

    if (bytes.size() < 2) {
        packet.errors.push_back("Packet too short (minimum 2 bytes required)");
        packet.totalBytes = bytes.size();
        return packet;
    }

    try {
        size_t offset = 0;

        // Parse header
        uint8_t header = bytes[0];
        uint8_t routeTypeVal = header & 0x03;
        uint8_t payloadTypeVal = (header >> 2) & 0x0F;
        uint8_t payloadVersionVal = (header >> 6) & 0x03;

        packet.routeType = static_cast<RouteType>(routeTypeVal);
        packet.payloadType = static_cast<PayloadType>(payloadTypeVal);
        packet.payloadVersion = static_cast<PayloadVersion>(payloadVersionVal);
        offset = 1;

        // Handle transport codes
        if (routeTypeVal == static_cast<uint8_t>(RouteType::TransportFlood) ||
            routeTypeVal == static_cast<uint8_t>(RouteType::TransportDirect)) {
            if (bytes.size() < offset + 4) {
                throw std::runtime_error("Packet too short for transport codes");
            }
            uint16_t code1 = bytes[offset] | (bytes[offset + 1] << 8);
            uint16_t code2 = bytes[offset + 2] | (bytes[offset + 3] << 8);
            packet.transportCodes = {code1, code2};
            offset += 4;
        }

        // Parse path
        if (bytes.size() < offset + 1) {
            throw std::runtime_error("Packet too short for path length");
        }
        packet.pathLength = bytes[offset];
        offset += 1;

        if (bytes.size() < offset + packet.pathLength) {
            throw std::runtime_error("Packet too short for path data");
        }

        if (packet.pathLength > 0) {
            std::vector<std::string> pathVec;
            for (uint8_t i = 0; i < packet.pathLength; i++) {
                pathVec.push_back(byteToHex(bytes[offset + i]));
            }
            packet.path = pathVec;
        }
        offset += packet.pathLength;

        // Extract payload
        const uint8_t* payloadBytes = bytes.data() + offset;
        size_t payloadLen = bytes.size() - offset;
        packet.payloadRaw = bytesToHex(payloadBytes, payloadLen);

        // Decode payload based on type
        switch (packet.payloadType) {
            case PayloadType::Advert: {
                auto advert = AdvertPayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = advert;
                break;
            }
            case PayloadType::Trace: {
                auto trace = TracePayloadDecoder::decode(payloadBytes, payloadLen, packet.path);
                packet.payloadDecoded = trace;
                break;
            }
            case PayloadType::GroupText: {
                auto groupText = GroupTextPayloadDecoder::decode(payloadBytes, payloadLen, keyStore);
                packet.payloadDecoded = groupText;
                break;
            }
            case PayloadType::Request: {
                auto request = RequestPayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = request;
                break;
            }
            case PayloadType::Response: {
                auto response = ResponsePayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = response;
                break;
            }
            case PayloadType::TextMessage: {
                auto textMsg = TextMessagePayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = textMsg;
                break;
            }
            case PayloadType::AnonRequest: {
                auto anonReq = AnonRequestPayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = anonReq;
                break;
            }
            case PayloadType::Ack: {
                auto ack = AckPayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = ack;
                break;
            }
            case PayloadType::Path: {
                auto path = PathPayloadDecoder::decode(payloadBytes, payloadLen);
                packet.payloadDecoded = path;
                break;
            }
            case PayloadType::Control: {
                auto controlResult = ControlPayloadDecoder::decode(payloadBytes, payloadLen);
                std::visit([&packet](auto&& arg) {
                    packet.payloadDecoded = arg;
                }, controlResult);
                break;
            }
            default:
                break;
        }

        // Calculate message hash
        packet.messageHash = calculateMessageHash(bytes.data(), bytes.size(),
                                                   routeTypeVal, payloadTypeVal, payloadVersionVal);

        packet.totalBytes = bytes.size();
        packet.isValid = true;

    } catch (const std::exception& e) {
        packet.totalBytes = bytes.size();
        packet.errors.push_back(e.what());
    }

    return packet;
}

DecodedPacket MeshCorePacketDecoder::decodeWithVerification(const std::string& hexData,
                                                            const MeshCoreKeyStore* keyStore) {
    auto packet = decode(hexData, keyStore);

    // If it's an advertisement, verify the signature
    if (packet.payloadType == PayloadType::Advert && packet.payloadDecoded.has_value()) {
        try {
            auto bytes = hexToBytes(hexData);
            size_t offset = 1;
            uint8_t routeTypeVal = bytes[0] & 0x03;
            if (routeTypeVal == static_cast<uint8_t>(RouteType::TransportFlood) ||
                routeTypeVal == static_cast<uint8_t>(RouteType::TransportDirect)) {
                offset += 4;
            }
            uint8_t pathLen = bytes[offset];
            offset += 1 + pathLen;

            const uint8_t* payloadBytes = bytes.data() + offset;
            size_t payloadLen = bytes.size() - offset;

            auto advert = AdvertPayloadDecoder::decodeWithVerification(payloadBytes, payloadLen);
            packet.payloadDecoded = advert;

            if (!advert.isValid) {
                packet.isValid = false;
                packet.errors = advert.errors;
            }
        } catch (...) {
            // Signature verification failed, keep original decode
        }
    }

    return packet;
}

PacketStructure MeshCorePacketDecoder::analyzeStructure(const std::string& hexData,
                                                        const MeshCoreKeyStore* keyStore) {
    PacketStructure structure;
    std::vector<uint8_t> bytes;
    try {
        bytes = hexToBytes(hexData);
    } catch (...) {
        return structure;
    }

    std::string upperHex = hexData;
    std::transform(upperHex.begin(), upperHex.end(), upperHex.begin(), ::toupper);
    structure.rawHex = upperHex;
    structure.totalBytes = bytes.size();

    if (bytes.size() < 2) return structure;

    try {
        size_t offset = 0;

        uint8_t header = bytes[0];
        uint8_t routeTypeVal = header & 0x03;
        uint8_t payloadTypeVal = (header >> 2) & 0x0F;
        uint8_t payloadVersionVal = (header >> 6) & 0x03;

        // Header segment
        PacketSegment headerSeg;
        headerSeg.name = "Header";
        headerSeg.description = "Header byte breakdown";
        headerSeg.startByte = 0;
        headerSeg.endByte = 0;
        headerSeg.value = "0x" + byteToHex(header);

        HeaderBreakdown hb;
        std::string fullBin;
        for (int i = 7; i >= 0; i--) fullBin += ((header >> i) & 1) ? '1' : '0';
        hb.fullBinary = fullBin;

        std::string routeBin;
        for (int i = 1; i >= 0; i--) routeBin += ((routeTypeVal >> i) & 1) ? '1' : '0';
        hb.fields.push_back({"0-1", "Route Type",
                            getRouteTypeName(static_cast<RouteType>(routeTypeVal)), routeBin});

        std::string payloadBin;
        for (int i = 3; i >= 0; i--) payloadBin += ((payloadTypeVal >> i) & 1) ? '1' : '0';
        hb.fields.push_back({"2-5", "Payload Type",
                            getPayloadTypeName(static_cast<PayloadType>(payloadTypeVal)), payloadBin});

        std::string versionBin;
        for (int i = 1; i >= 0; i--) versionBin += ((payloadVersionVal >> i) & 1) ? '1' : '0';
        hb.fields.push_back({"6-7", "Version", std::to_string(payloadVersionVal), versionBin});

        headerSeg.headerBreakdown = hb;
        structure.segments.push_back(headerSeg);
        offset = 1;

        // Transport codes
        if (routeTypeVal == static_cast<uint8_t>(RouteType::TransportFlood) ||
            routeTypeVal == static_cast<uint8_t>(RouteType::TransportDirect)) {
            uint32_t transportCode = readUint32LE(bytes.data(), offset);
            std::ostringstream tcVal;
            tcVal << "0x" << std::hex << std::setfill('0') << std::setw(8) << transportCode;
            structure.segments.push_back({"Transport Code", "Used for Direct/Response routing",
                                         static_cast<int>(offset), static_cast<int>(offset) + 3,
                                         tcVal.str()});
            offset += 4;
        }

        // Path length
        uint8_t pathLength = bytes[offset];
        std::string pathLenDesc = std::to_string(pathLength) + " bytes";
        if (routeTypeVal == static_cast<uint8_t>(RouteType::Direct) ||
            routeTypeVal == static_cast<uint8_t>(RouteType::TransportDirect)) {
            pathLenDesc = std::to_string(pathLength) + " bytes of routing instructions";
        } else if (routeTypeVal == static_cast<uint8_t>(RouteType::Flood) ||
                   routeTypeVal == static_cast<uint8_t>(RouteType::TransportFlood)) {
            pathLenDesc = std::to_string(pathLength) + " bytes showing route taken";
        }
        structure.segments.push_back({"Path Length", pathLenDesc,
                                     static_cast<int>(offset), static_cast<int>(offset),
                                     "0x" + byteToHex(pathLength)});
        offset += 1;

        // Path data
        if (pathLength > 0) {
            if (payloadTypeVal == static_cast<uint8_t>(PayloadType::Trace)) {
                std::string snrDesc = "SNR values: ";
                for (uint8_t i = 0; i < pathLength; i++) {
                    uint8_t snrRaw = bytes[offset + i];
                    int8_t snrSigned = snrRaw > 127 ? static_cast<int8_t>(snrRaw - 256) : static_cast<int8_t>(snrRaw);
                    double snrDb = snrSigned / 4.0;
                    if (i > 0) snrDesc += ", ";
                    std::ostringstream snrOss;
                    snrOss << std::fixed << std::setprecision(2) << snrDb << "dB";
                    snrDesc += snrOss.str();
                }
                structure.segments.push_back({"Path SNR Data", snrDesc,
                                             static_cast<int>(offset), static_cast<int>(offset) + pathLength - 1,
                                             bytesToHex(bytes.data() + offset, pathLength)});
            } else {
                std::string pathDesc = "Routing path information";
                structure.segments.push_back({"Path Data", pathDesc,
                                             static_cast<int>(offset), static_cast<int>(offset) + pathLength - 1,
                                             bytesToHex(bytes.data() + offset, pathLength)});
            }
            offset += pathLength;
        }

        // Payload segment
        if (bytes.size() > offset) {
            structure.segments.push_back({"Payload",
                                         getPayloadTypeName(static_cast<PayloadType>(payloadTypeVal)) + " payload data",
                                         static_cast<int>(offset), static_cast<int>(bytes.size()) - 1,
                                         bytesToHex(bytes.data() + offset, bytes.size() - offset)});
        }

        // Payload-specific segments
        const uint8_t* payloadBytes = bytes.data() + offset;
        size_t payloadLen = bytes.size() - offset;

        structure.payload.hex = bytesToHex(payloadBytes, payloadLen);
        structure.payload.startByte = static_cast<int>(offset);
        structure.payload.type = getPayloadTypeName(static_cast<PayloadType>(payloadTypeVal));

        switch (static_cast<PayloadType>(payloadTypeVal)) {
            case PayloadType::Advert:
                structure.payload.segments = AdvertPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::Trace:
                structure.payload.segments = TracePayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::GroupText:
                structure.payload.segments = GroupTextPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::Request:
                structure.payload.segments = RequestPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::Response:
                structure.payload.segments = ResponsePayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::TextMessage:
                structure.payload.segments = TextMessagePayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::AnonRequest:
                structure.payload.segments = AnonRequestPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::Ack:
                structure.payload.segments = AckPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            case PayloadType::Control:
                structure.payload.segments = ControlPayloadDecoder::generateSegments(payloadBytes, payloadLen, 0);
                break;
            default:
                if (payloadLen > 0) {
                    structure.payload.segments.push_back({
                        getPayloadTypeName(static_cast<PayloadType>(payloadTypeVal)) + " Payload",
                        "Raw payload data (" + std::to_string(payloadLen) + " bytes)",
                        0, static_cast<int>(payloadLen) - 1,
                        bytesToHex(payloadBytes, payloadLen)
                    });
                }
                break;
        }

        structure.messageHash = calculateMessageHash(bytes.data(), bytes.size(),
                                                      routeTypeVal, payloadTypeVal, payloadVersionVal);

    } catch (...) {
        // Structure analysis failed
    }

    return structure;
}

PacketStructure MeshCorePacketDecoder::analyzeStructureWithVerification(const std::string& hexData,
                                                                        const MeshCoreKeyStore* keyStore) {
    // For now, same as analyzeStructure (verification adds signature info to advert segments)
    return analyzeStructure(hexData, keyStore);
}

ValidationResult MeshCorePacketDecoder::validate(const std::string& hexData) {
    ValidationResult result;
    std::vector<uint8_t> bytes;
    try {
        bytes = hexToBytes(hexData);
    } catch (const std::exception& e) {
        result.errors.push_back(e.what());
        return result;
    }

    if (bytes.size() < 2) {
        result.errors.push_back("Packet too short (minimum 2 bytes required)");
        return result;
    }

    try {
        size_t offset = 1;

        uint8_t routeType = bytes[0] & 0x03;
        if (routeType == static_cast<uint8_t>(RouteType::TransportFlood) ||
            routeType == static_cast<uint8_t>(RouteType::TransportDirect)) {
            if (bytes.size() < offset + 4) {
                result.errors.push_back("Packet too short for transport codes");
            }
            offset += 4;
        }

        if (bytes.size() < offset + 1) {
            result.errors.push_back("Packet too short for path length");
        } else {
            uint8_t pathLength = bytes[offset];
            offset += 1;
            if (bytes.size() < offset + pathLength) {
                result.errors.push_back("Packet too short for path data");
            }
            offset += pathLength;
        }

        if (offset >= bytes.size()) {
            result.errors.push_back("No payload data found");
        }
    } catch (const std::exception& e) {
        result.errors.push_back(e.what());
    }

    result.isValid = result.errors.empty();
    return result;
}

std::string MeshCorePacketDecoder::calculateMessageHash(const uint8_t* bytes, size_t len,
                                                        uint8_t routeType, uint8_t payloadType,
                                                        uint8_t payloadVersion) {
    // For TRACE packets, use the trace tag as hash
    if (payloadType == static_cast<uint8_t>(PayloadType::Trace) && len >= 13) {
        size_t offset = 1;

        if (routeType == static_cast<uint8_t>(RouteType::TransportFlood) ||
            routeType == static_cast<uint8_t>(RouteType::TransportDirect)) {
            offset += 4;
        }

        if (len > offset) {
            uint8_t pathLen = bytes[offset];
            offset += 1 + pathLen;
        }

        if (len >= offset + 4) {
            uint32_t traceTag = readUint32LE(bytes, offset);
            return numberToHex(traceTag, 8);
        }
    }

    // For other packets, create hash from constant parts
    uint8_t constantHeader = (payloadType << 2) | (payloadVersion << 6);
    size_t offset = 1;

    if (routeType == static_cast<uint8_t>(RouteType::TransportFlood) ||
        routeType == static_cast<uint8_t>(RouteType::TransportDirect)) {
        offset += 4;
    }

    if (len > offset) {
        uint8_t pathLen = bytes[offset];
        offset += 1 + pathLen;
    }

    // Generate hash (same algorithm as TypeScript version)
    int32_t hash = 0;
    // First byte is the constant header
    hash = ((hash << 5) - hash + constantHeader) & 0xFFFFFFFF;
    // Then the payload data
    for (size_t i = offset; i < len; i++) {
        hash = ((hash << 5) - hash + bytes[i]) & 0xFFFFFFFF;
    }

    return numberToHex(static_cast<uint32_t>(hash), 8);
}

} // namespace meshcore
