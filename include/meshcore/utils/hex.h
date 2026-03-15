// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace meshcore {

std::string byteToHex(uint8_t byte);
std::string bytesToHex(const uint8_t* data, size_t len);
std::string bytesToHex(const std::vector<uint8_t>& bytes);
std::string numberToHex(uint32_t num, int padLength = 8);
std::vector<uint8_t> hexToBytes(const std::string& hex);

} // namespace meshcore
