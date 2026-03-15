// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace meshcore {

std::string base64urlEncode(const std::vector<uint8_t>& data);
std::string base64urlEncode(const std::string& data);
std::vector<uint8_t> base64urlDecode(const std::string& str);

} // namespace meshcore
