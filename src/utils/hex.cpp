// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/utils/hex.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace meshcore {

std::string byteToHex(uint8_t byte) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", byte);
    return std::string(buf);
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += byteToHex(data[i]);
    }
    return result;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    return bytesToHex(bytes.data(), bytes.size());
}

std::string numberToHex(uint32_t num, int padLength) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%0*X", padLength, num);
    return std::string(buf);
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    // Remove whitespace
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }

    // Validate hex characters
    for (char c : clean) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            throw std::runtime_error("Invalid hex string: invalid characters");
        }
    }

    if (clean.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string: odd length");
    }

    std::vector<uint8_t> bytes(clean.length() / 2);
    for (size_t i = 0; i < clean.length(); i += 2) {
        bytes[i / 2] = static_cast<uint8_t>(
            std::stoi(clean.substr(i, 2), nullptr, 16)
        );
    }

    return bytes;
}

} // namespace meshcore
