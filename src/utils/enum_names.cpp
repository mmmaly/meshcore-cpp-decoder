// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/utils/enum_names.h"
#include <sstream>

namespace meshcore {

std::string getRouteTypeName(RouteType routeType) {
    switch (routeType) {
        case RouteType::Flood: return "Flood";
        case RouteType::Direct: return "Direct";
        case RouteType::TransportFlood: return "TransportFlood";
        case RouteType::TransportDirect: return "TransportDirect";
        default: return "Unknown (" + std::to_string(static_cast<int>(routeType)) + ")";
    }
}

std::string getPayloadTypeName(PayloadType payloadType) {
    switch (payloadType) {
        case PayloadType::RawCustom: return "RawCustom";
        case PayloadType::Trace: return "Trace";
        case PayloadType::Advert: return "Advert";
        case PayloadType::GroupText: return "GroupText";
        case PayloadType::GroupData: return "GroupData";
        case PayloadType::Request: return "Request";
        case PayloadType::Response: return "Response";
        case PayloadType::TextMessage: return "TextMessage";
        case PayloadType::AnonRequest: return "AnonRequest";
        case PayloadType::Ack: return "Ack";
        case PayloadType::Path: return "Path";
        case PayloadType::Multipart: return "Multipart";
        case PayloadType::Control: return "Control";
        default: {
            std::ostringstream oss;
            oss << "Unknown (0x" << std::hex << static_cast<int>(payloadType) << ")";
            return oss.str();
        }
    }
}

std::string getPayloadVersionName(PayloadVersion version) {
    switch (version) {
        case PayloadVersion::Version1: return "Version 1";
        case PayloadVersion::Version2: return "Version 2";
        case PayloadVersion::Version3: return "Version 3";
        case PayloadVersion::Version4: return "Version 4";
        default: return "Unknown (" + std::to_string(static_cast<int>(version)) + ")";
    }
}

std::string getDeviceRoleName(DeviceRole role) {
    switch (role) {
        case DeviceRole::Unknown: return "Unknown";
        case DeviceRole::ChatNode: return "Chat Node";
        case DeviceRole::Repeater: return "Repeater";
        case DeviceRole::RoomServer: return "Room Server";
        case DeviceRole::Sensor: return "Sensor";
        default: return "Unknown (" + std::to_string(static_cast<int>(role)) + ")";
    }
}

std::string getRequestTypeName(RequestType requestType) {
    switch (requestType) {
        case RequestType::GetStats: return "Get Stats";
        case RequestType::Keepalive: return "Keepalive (deprecated)";
        case RequestType::GetTelemetryData: return "Get Telemetry Data";
        case RequestType::GetMinMaxAvgData: return "Get Min/Max/Avg Data";
        case RequestType::GetAccessList: return "Get Access List";
        default: return "Unknown (" + std::to_string(static_cast<int>(requestType)) + ")";
    }
}

std::string getControlSubTypeName(ControlSubType subType) {
    switch (subType) {
        case ControlSubType::NodeDiscoverReq: return "Node Discover Request";
        case ControlSubType::NodeDiscoverResp: return "Node Discover Response";
        default: {
            std::ostringstream oss;
            oss << "Unknown (0x" << std::hex << static_cast<int>(subType) << ")";
            return oss.str();
        }
    }
}

} // namespace meshcore
