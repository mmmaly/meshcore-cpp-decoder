// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <variant>
#include "enums.h"

namespace meshcore {

struct BasePayload {
    PayloadType type;
    PayloadVersion version = PayloadVersion::Version1;
    bool isValid = true;
    std::vector<std::string> errors;
};

struct AdvertAppData {
    uint8_t flags = 0;
    DeviceRole deviceRole = DeviceRole::ChatNode;
    bool hasLocation = false;
    bool hasName = false;
    std::optional<double> latitude;
    std::optional<double> longitude;
    std::optional<std::string> name;
};

struct AdvertPayload : BasePayload {
    std::string publicKey;
    uint32_t timestamp = 0;
    std::string signature;
    std::optional<bool> signatureValid;
    std::optional<std::string> signatureError;
    AdvertAppData appData;
};

struct TracePayload : BasePayload {
    std::string traceTag;
    uint32_t authCode = 0;
    uint8_t flags = 0;
    std::vector<std::string> pathHashes;
    std::optional<std::vector<double>> snrValues;
};

struct GroupTextDecrypted {
    uint32_t timestamp = 0;
    uint8_t flags = 0;
    std::optional<std::string> sender;
    std::string message;
};

struct GroupTextPayload : BasePayload {
    std::string channelHash;
    std::string cipherMac;
    std::string ciphertext;
    size_t ciphertextLength = 0;
    std::optional<GroupTextDecrypted> decrypted;
};

struct RequestPayload : BasePayload {
    std::string destinationHash;
    std::string sourceHash;
    std::string cipherMac;
    std::string ciphertext;
    uint32_t timestamp = 0;
    RequestType requestType = RequestType::GetStats;
    std::string requestData;
};

struct TextMessagePayload : BasePayload {
    std::string destinationHash;
    std::string sourceHash;
    std::string cipherMac;
    std::string ciphertext;
    size_t ciphertextLength = 0;
};

struct AnonRequestPayload : BasePayload {
    std::string destinationHash;
    std::string senderPublicKey;
    std::string cipherMac;
    std::string ciphertext;
    size_t ciphertextLength = 0;
};

struct AckPayload : BasePayload {
    std::string checksum;
};

struct PathPayload : BasePayload {
    uint8_t pathLength = 0;
    std::vector<std::string> pathHashes;
    uint8_t extraType = 0;
    std::string extraData;
};

struct ResponsePayload : BasePayload {
    std::string destinationHash;
    std::string sourceHash;
    std::string cipherMac;
    std::string ciphertext;
    size_t ciphertextLength = 0;
};

struct ControlDiscoverReqPayload : BasePayload {
    ControlSubType subType = ControlSubType::NodeDiscoverReq;
    uint8_t rawFlags = 0;
    bool prefixOnly = false;
    uint8_t typeFilter = 0;
    std::vector<std::string> typeFilterNames;
    uint32_t tag = 0;
    uint32_t since = 0;
};

struct ControlDiscoverRespPayload : BasePayload {
    ControlSubType subType = ControlSubType::NodeDiscoverResp;
    uint8_t rawFlags = 0;
    DeviceRole nodeType = DeviceRole::Unknown;
    std::string nodeTypeName;
    double snr = 0.0;
    uint32_t tag = 0;
    std::string publicKey;
    size_t publicKeyLength = 0;
};

using ControlPayload = std::variant<ControlDiscoverReqPayload, ControlDiscoverRespPayload>;

using PayloadData = std::variant<
    AdvertPayload,
    TracePayload,
    GroupTextPayload,
    RequestPayload,
    TextMessagePayload,
    AnonRequestPayload,
    AckPayload,
    PathPayload,
    ResponsePayload,
    ControlDiscoverReqPayload,
    ControlDiscoverRespPayload
>;

} // namespace meshcore
