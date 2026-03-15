// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/advert.h"
#include "meshcore/utils/hex.h"
#include "meshcore/utils/enum_names.h"
#include "meshcore/crypto/ed25519.h"
#include <cstring>
#include <sstream>
#include <algorithm>

namespace meshcore {

uint32_t AdvertPayloadDecoder::readUint32LE(const uint8_t* buf, size_t offset) {
    return static_cast<uint32_t>(buf[offset]) |
           (static_cast<uint32_t>(buf[offset + 1]) << 8) |
           (static_cast<uint32_t>(buf[offset + 2]) << 16) |
           (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

int32_t AdvertPayloadDecoder::readInt32LE(const uint8_t* buf, size_t offset) {
    uint32_t value = readUint32LE(buf, offset);
    return static_cast<int32_t>(value);
}

DeviceRole AdvertPayloadDecoder::parseDeviceRole(uint8_t flags) {
    uint8_t roleValue = flags & 0x0F;
    switch (roleValue) {
        case 0x01: return DeviceRole::ChatNode;
        case 0x02: return DeviceRole::Repeater;
        case 0x03: return DeviceRole::RoomServer;
        case 0x04: return DeviceRole::Sensor;
        default: return DeviceRole::ChatNode;
    }
}

std::string AdvertPayloadDecoder::sanitizeControlCharacters(const std::string& value) {
    std::string result;
    for (char c : value) {
        if (c >= 0x20 && c != 0x7F) {
            result += c;
        } else if ((static_cast<unsigned char>(c) & 0x80) != 0) {
            // Keep UTF-8 continuation bytes
            result += c;
        }
    }
    // Trim whitespace
    size_t start = result.find_first_not_of(" \t\r\n");
    size_t end = result.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return result.substr(start, end - start + 1);
}

AdvertPayload AdvertPayloadDecoder::decode(const uint8_t* payload, size_t len) {
    AdvertPayload advert;
    advert.type = PayloadType::Advert;
    advert.version = PayloadVersion::Version1;

    if (len < 101) {
        advert.isValid = false;
        advert.errors.push_back("Advertisement payload too short");
        advert.appData.deviceRole = DeviceRole::ChatNode;
        return advert;
    }

    try {
        size_t offset = 0;

        // Public key (32 bytes)
        advert.publicKey = bytesToHex(payload + offset, 32);
        offset += 32;

        // Timestamp (4 bytes LE)
        advert.timestamp = readUint32LE(payload, offset);
        offset += 4;

        // Signature (64 bytes)
        advert.signature = bytesToHex(payload + offset, 64);
        offset += 64;

        // Flags (1 byte)
        uint8_t flags = payload[offset];
        offset += 1;

        advert.appData.flags = flags;
        advert.appData.deviceRole = parseDeviceRole(flags);
        advert.appData.hasLocation = (flags & AdvertFlags::HasLocation) != 0;
        advert.appData.hasName = (flags & AdvertFlags::HasName) != 0;

        // Location data (if HasLocation)
        if ((flags & AdvertFlags::HasLocation) && len >= offset + 8) {
            double lat = readInt32LE(payload, offset) / 1000000.0;
            double lon = readInt32LE(payload, offset + 4) / 1000000.0;
            advert.appData.latitude = lat;
            advert.appData.longitude = lon;
            offset += 8;
        }

        // Skip feature fields
        if (flags & AdvertFlags::HasFeature1) offset += 2;
        if (flags & AdvertFlags::HasFeature2) offset += 2;

        // Name data (if HasName)
        if ((flags & AdvertFlags::HasName) && len > offset) {
            std::string rawName(reinterpret_cast<const char*>(payload + offset), len - offset);
            auto nullPos = rawName.find('\0');
            if (nullPos != std::string::npos) {
                rawName = rawName.substr(0, nullPos);
            }
            std::string sanitized = sanitizeControlCharacters(rawName);
            advert.appData.name = sanitized.empty() ? rawName : sanitized;
        }

        advert.isValid = true;
    } catch (const std::exception& e) {
        advert.isValid = false;
        advert.errors.push_back(e.what());
    }

    return advert;
}

AdvertPayload AdvertPayloadDecoder::decodeWithVerification(const uint8_t* payload, size_t len) {
    auto advert = decode(payload, len);
    if (!advert.isValid) return advert;

    try {
        size_t appDataStart = 32 + 4 + 64;
        std::string appDataHex = bytesToHex(payload + appDataStart, len - appDataStart);

        bool valid = Ed25519::verifyAdvertisementSignature(
            advert.publicKey, advert.signature, advert.timestamp, appDataHex
        );

        advert.signatureValid = valid;
        if (!valid) {
            advert.signatureError = "Ed25519 signature verification failed";
            advert.isValid = false;
            advert.errors.push_back("Invalid Ed25519 signature");
        }
    } catch (const std::exception& e) {
        advert.signatureValid = false;
        advert.signatureError = e.what();
        advert.isValid = false;
        advert.errors.push_back(std::string("Signature verification failed: ") + e.what());
    }

    return advert;
}

std::vector<PayloadSegment> AdvertPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 101) {
        segments.push_back({"Invalid Advert Data", "Advert payload too short (minimum 101 bytes required)",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;

    segments.push_back({"Public Key", "Ed25519 public key",
                        segmentOffset + offset, segmentOffset + offset + 31,
                        bytesToHex(payload + offset, 32)});
    offset += 32;

    uint32_t ts = readUint32LE(payload, offset);
    std::ostringstream tsDesc;
    tsDesc << ts << " (timestamp)";
    segments.push_back({"Timestamp", tsDesc.str(),
                        segmentOffset + offset, segmentOffset + offset + 3,
                        bytesToHex(payload + offset, 4)});
    offset += 4;

    segments.push_back({"Signature", "Ed25519 signature",
                        segmentOffset + offset, segmentOffset + offset + 63,
                        bytesToHex(payload + offset, 64)});
    offset += 64;

    uint8_t flags = payload[offset];
    auto role = parseDeviceRole(flags);
    std::ostringstream flagsDesc;
    flagsDesc << "Binary: ";
    for (int i = 7; i >= 0; i--) flagsDesc << ((flags >> i) & 1);
    flagsDesc << " | Role: " << getDeviceRoleName(role)
              << " | Location: " << ((flags & AdvertFlags::HasLocation) ? "Yes" : "No")
              << " | Name: " << ((flags & AdvertFlags::HasName) ? "Yes" : "No");
    segments.push_back({"App Flags", flagsDesc.str(),
                        segmentOffset + offset, segmentOffset + offset,
                        byteToHex(flags)});
    offset += 1;

    if ((flags & AdvertFlags::HasLocation) && len >= static_cast<size_t>(offset) + 8) {
        double lat = readInt32LE(payload, offset) / 1000000.0;
        double lon = readInt32LE(payload, offset + 4) / 1000000.0;

        std::ostringstream latDesc, lonDesc;
        latDesc << lat << "°";
        lonDesc << lon << "°";

        segments.push_back({"Latitude", latDesc.str(),
                            segmentOffset + offset, segmentOffset + offset + 3,
                            bytesToHex(payload + offset, 4)});
        segments.push_back({"Longitude", lonDesc.str(),
                            segmentOffset + offset + 4, segmentOffset + offset + 7,
                            bytesToHex(payload + offset + 4, 4)});
        offset += 8;
    }

    if (flags & AdvertFlags::HasFeature1) offset += 2;
    if (flags & AdvertFlags::HasFeature2) offset += 2;

    if ((flags & AdvertFlags::HasName) && len > static_cast<size_t>(offset)) {
        std::string name(reinterpret_cast<const char*>(payload + offset), len - offset);
        auto nullPos = name.find('\0');
        if (nullPos != std::string::npos) name = name.substr(0, nullPos);

        segments.push_back({"Node Name", "Node name: \"" + name + "\"",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
