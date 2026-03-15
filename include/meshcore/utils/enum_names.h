// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include "../types/enums.h"

namespace meshcore {

std::string getRouteTypeName(RouteType routeType);
std::string getPayloadTypeName(PayloadType payloadType);
std::string getPayloadVersionName(PayloadVersion version);
std::string getDeviceRoleName(DeviceRole role);
std::string getRequestTypeName(RequestType requestType);
std::string getControlSubTypeName(ControlSubType subType);

} // namespace meshcore
