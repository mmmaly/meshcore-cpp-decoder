// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/control.h"
#include "meshcore/utils/hex.h"
#include "meshcore/utils/enum_names.h"
#include <sstream>

namespace meshcore {

uint32_t ControlPayloadDecoder::readUint32LE(const uint8_t* buf, size_t offset) {
    return (static_cast<uint32_t>(buf[offset]) |
            (static_cast<uint32_t>(buf[offset + 1]) << 8) |
            (static_cast<uint32_t>(buf[offset + 2]) << 16) |
            (static_cast<uint32_t>(buf[offset + 3]) << 24));
}

std::vector<std::string> ControlPayloadDecoder::parseTypeFilter(uint8_t filter) {
    std::vector<std::string> types;
    if (filter & (1 << static_cast<int>(DeviceRole::ChatNode))) types.push_back("Chat");
    if (filter & (1 << static_cast<int>(DeviceRole::Repeater))) types.push_back("Repeater");
    if (filter & (1 << static_cast<int>(DeviceRole::RoomServer))) types.push_back("Room");
    if (filter & (1 << static_cast<int>(DeviceRole::Sensor))) types.push_back("Sensor");
    return types;
}

ControlPayloadDecoder::Result ControlPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    if (len < 1) {
        ControlDiscoverReqPayload err;
        err.type = PayloadType::Control;
        err.version = PayloadVersion::Version1;
        err.isValid = false;
        err.errors.push_back("Control payload too short");
        err.subType = ControlSubType::NodeDiscoverReq;
        return err;
    }

    uint8_t subType = payload[0] & 0xF0;

    switch (subType) {
        case static_cast<uint8_t>(ControlSubType::NodeDiscoverReq):
            return decodeDiscoverReq(payload, len);
        case static_cast<uint8_t>(ControlSubType::NodeDiscoverResp):
            return decodeDiscoverResp(payload, len);
        default: {
            ControlDiscoverReqPayload err;
            err.type = PayloadType::Control;
            err.version = PayloadVersion::Version1;
            err.isValid = false;
            std::ostringstream oss;
            oss << "Unknown control sub-type: 0x" << std::hex << static_cast<int>(subType);
            err.errors.push_back(oss.str());
            err.subType = ControlSubType::NodeDiscoverReq;
            err.rawFlags = payload[0];
            return err;
        }
    }
}

ControlDiscoverReqPayload ControlPayloadDecoder::decodeDiscoverReq(const uint8_t* payload, size_t len) {
    ControlDiscoverReqPayload req;
    req.type = PayloadType::Control;
    req.version = PayloadVersion::Version1;
    req.subType = ControlSubType::NodeDiscoverReq;

    if (len < 6) {
        req.isValid = false;
        req.errors.push_back("DISCOVER_REQ payload too short");
        req.rawFlags = len > 0 ? payload[0] : 0;
        return req;
    }

    size_t offset = 0;

    req.rawFlags = payload[offset];
    req.prefixOnly = (req.rawFlags & 0x01) != 0;
    offset += 1;

    req.typeFilter = payload[offset];
    req.typeFilterNames = parseTypeFilter(req.typeFilter);
    offset += 1;

    req.tag = readUint32LE(payload, offset);
    offset += 4;

    if (len >= offset + 4) {
        req.since = readUint32LE(payload, offset);
    }

    req.isValid = true;
    return req;
}

ControlDiscoverRespPayload ControlPayloadDecoder::decodeDiscoverResp(const uint8_t* payload, size_t len) {
    ControlDiscoverRespPayload resp;
    resp.type = PayloadType::Control;
    resp.version = PayloadVersion::Version1;
    resp.subType = ControlSubType::NodeDiscoverResp;

    if (len < 14) {
        resp.isValid = false;
        resp.errors.push_back("DISCOVER_RESP payload too short");
        resp.rawFlags = len > 0 ? payload[0] : 0;
        return resp;
    }

    size_t offset = 0;

    resp.rawFlags = payload[offset];
    resp.nodeType = static_cast<DeviceRole>(resp.rawFlags & 0x0F);
    resp.nodeTypeName = getDeviceRoleName(resp.nodeType);
    offset += 1;

    uint8_t snrRaw = payload[offset];
    int8_t snrSigned = snrRaw > 127 ? static_cast<int8_t>(snrRaw - 256) : static_cast<int8_t>(snrRaw);
    resp.snr = snrSigned / 4.0;
    offset += 1;

    resp.tag = readUint32LE(payload, offset);
    offset += 4;

    resp.publicKeyLength = len - offset;
    resp.publicKey = bytesToHex(payload + offset, resp.publicKeyLength);

    resp.isValid = true;
    return resp;
}

std::vector<PayloadSegment> ControlPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 1) return segments;

    uint8_t subType = payload[0] & 0xF0;

    if (subType == static_cast<uint8_t>(ControlSubType::NodeDiscoverReq) && len >= 6) {
        int offset = 0;
        uint8_t flags = payload[offset];
        bool prefixOnly = (flags & 0x01) != 0;
        segments.push_back({"Flags", "Sub-type: DISCOVER_REQ | Prefix Only: " + std::string(prefixOnly ? "true" : "false"),
                            segmentOffset + offset, segmentOffset + offset, byteToHex(flags)});
        offset += 1;

        uint8_t filter = payload[offset];
        auto filterNames = parseTypeFilter(filter);
        std::string filterStr;
        for (size_t i = 0; i < filterNames.size(); i++) {
            if (i > 0) filterStr += ", ";
            filterStr += filterNames[i];
        }
        segments.push_back({"Type Filter", "Filter: " + (filterStr.empty() ? "None" : filterStr),
                            segmentOffset + offset, segmentOffset + offset, byteToHex(filter)});
        offset += 1;

        uint32_t tag = readUint32LE(payload, offset);
        std::ostringstream tagDesc;
        tagDesc << "Tag: 0x" << std::hex << tag;
        segments.push_back({"Tag", tagDesc.str(),
                            segmentOffset + offset, segmentOffset + offset + 3, bytesToHex(payload + offset, 4)});
        offset += 4;

        if (len >= static_cast<size_t>(offset) + 4) {
            uint32_t since = readUint32LE(payload, offset);
            segments.push_back({"Since", "Filter timestamp: " + std::to_string(since),
                                segmentOffset + offset, segmentOffset + offset + 3, bytesToHex(payload + offset, 4)});
        }
    } else if (subType == static_cast<uint8_t>(ControlSubType::NodeDiscoverResp) && len >= 14) {
        int offset = 0;
        uint8_t flags = payload[offset];
        auto nodeType = static_cast<DeviceRole>(flags & 0x0F);
        segments.push_back({"Flags", "Sub-type: DISCOVER_RESP | Node Type: " + getDeviceRoleName(nodeType),
                            segmentOffset + offset, segmentOffset + offset, byteToHex(flags)});
        offset += 1;

        uint8_t snrRaw = payload[offset];
        int8_t snrSigned = snrRaw > 127 ? static_cast<int8_t>(snrRaw - 256) : static_cast<int8_t>(snrRaw);
        double snr = snrSigned / 4.0;
        std::ostringstream snrDesc;
        snrDesc << "Inbound SNR: " << snr << " dB";
        segments.push_back({"SNR", snrDesc.str(),
                            segmentOffset + offset, segmentOffset + offset, byteToHex(snrRaw)});
        offset += 1;

        uint32_t tag = readUint32LE(payload, offset);
        std::ostringstream tagDesc;
        tagDesc << "Tag: 0x" << std::hex << tag;
        segments.push_back({"Tag", tagDesc.str(),
                            segmentOffset + offset, segmentOffset + offset + 3, bytesToHex(payload + offset, 4)});
        offset += 4;

        size_t pkLen = len - offset;
        std::string keyType = pkLen == 32 ? "Full Public Key" : "Public Key Prefix";
        segments.push_back({keyType, keyType + " (" + std::to_string(pkLen) + " bytes)",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, pkLen)});
    }

    return segments;
}

} // namespace meshcore
