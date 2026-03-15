// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <cstdint>

namespace meshcore {

enum class RouteType : uint8_t {
    TransportFlood = 0x00,
    Flood = 0x01,
    Direct = 0x02,
    TransportDirect = 0x03
};

enum class PayloadType : uint8_t {
    Request = 0x00,
    Response = 0x01,
    TextMessage = 0x02,
    Ack = 0x03,
    Advert = 0x04,
    GroupText = 0x05,
    GroupData = 0x06,
    AnonRequest = 0x07,
    Path = 0x08,
    Trace = 0x09,
    Multipart = 0x0A,
    Control = 0x0B,
    RawCustom = 0x0F
};

enum class ControlSubType : uint8_t {
    NodeDiscoverReq = 0x80,
    NodeDiscoverResp = 0x90
};

enum class PayloadVersion : uint8_t {
    Version1 = 0x00,
    Version2 = 0x01,
    Version3 = 0x02,
    Version4 = 0x03
};

enum class DeviceRole : uint8_t {
    Unknown = 0x00,
    ChatNode = 0x01,
    Repeater = 0x02,
    RoomServer = 0x03,
    Sensor = 0x04
};

enum AdvertFlags : uint8_t {
    HasLocation = 0x10,
    HasFeature1 = 0x20,
    HasFeature2 = 0x40,
    HasName = 0x80
};

enum class RequestType : uint8_t {
    GetStats = 0x01,
    Keepalive = 0x02,
    GetTelemetryData = 0x03,
    GetMinMaxAvgData = 0x04,
    GetAccessList = 0x05
};

} // namespace meshcore
