// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/utils/base64.h"
#include <stdexcept>

namespace meshcore {

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64Encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result += base64_chars[(n >> 18) & 0x3F];
        result += base64_chars[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[n & 0x3F] : '=';
    }

    return result;
}

static uint8_t base64CharToValue(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return 0xFF;
}

std::string base64urlEncode(const std::vector<uint8_t>& data) {
    std::string b64 = base64Encode(data.data(), data.size());
    // Make URL-safe and remove padding
    std::string result;
    result.reserve(b64.size());
    for (char c : b64) {
        if (c == '+') result += '-';
        else if (c == '/') result += '_';
        else if (c != '=') result += c;
    }
    return result;
}

std::string base64urlEncode(const std::string& data) {
    return base64urlEncode(std::vector<uint8_t>(data.begin(), data.end()));
}

std::vector<uint8_t> base64urlDecode(const std::string& str) {
    // Convert back from URL-safe format and add padding
    std::string base64 = str;
    for (char& c : base64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (base64.length() % 4) {
        base64 += '=';
    }

    std::vector<uint8_t> result;
    result.reserve((base64.length() / 4) * 3);

    for (size_t i = 0; i < base64.length(); i += 4) {
        uint32_t n = 0;
        int pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = base64[i + j];
            if (c == '=') {
                pad++;
                n <<= 6;
            } else {
                uint8_t v = base64CharToValue(c);
                if (v == 0xFF) throw std::runtime_error("Invalid base64 character");
                n = (n << 6) | v;
            }
        }
        result.push_back((n >> 16) & 0xFF);
        if (pad < 2) result.push_back((n >> 8) & 0xFF);
        if (pad < 1) result.push_back(n & 0xFF);
    }

    return result;
}

} // namespace meshcore
