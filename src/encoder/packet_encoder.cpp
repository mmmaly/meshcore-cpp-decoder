// Copyright (c) 2026
// MIT License

#include "meshcore/encoder/packet_encoder.h"
#include "meshcore/crypto/channel_crypto.h"
#include "meshcore/crypto/ed25519.h"
#include "meshcore/utils/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>

namespace meshcore {

EncodeResult MeshCorePacketEncoder::buildPacket(
    RouteType routeType,
    PayloadType payloadType,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& path,
    uint8_t pathHashSize,
    std::optional<std::pair<uint16_t, uint16_t>> transportCodes,
    PayloadVersion version
) {
    EncodeResult result;
    if (pathHashSize < 1 || pathHashSize > 4) {
        result.error = "path hash size must be 1-4 bytes";
        return result;
    }
    if (path.size() % pathHashSize != 0) {
        result.error = "path length is not a multiple of the hash size";
        return result;
    }
    size_t hashCount = path.size() / pathHashSize;
    if (hashCount > 63) {
        result.error = "path holds at most 63 hashes";
        return result;
    }
    bool transport = routeType == RouteType::TransportFlood ||
                     routeType == RouteType::TransportDirect;
    if (transport && !transportCodes) {
        result.error = "transport route types need transport codes";
        return result;
    }

    result.bytes.reserve(1 + (transport ? 4 : 0) + 1 + path.size() + payload.size());
    result.bytes.push_back(static_cast<uint8_t>(
        (static_cast<uint8_t>(routeType) & 0x03) |
        ((static_cast<uint8_t>(payloadType) & 0x0F) << 2) |
        ((static_cast<uint8_t>(version) & 0x03) << 6)));

    if (transport) {
        result.bytes.push_back(transportCodes->first & 0xFF);
        result.bytes.push_back(transportCodes->first >> 8);
        result.bytes.push_back(transportCodes->second & 0xFF);
        result.bytes.push_back(transportCodes->second >> 8);
    }

    result.bytes.push_back(static_cast<uint8_t>(
        (hashCount & 63) | ((pathHashSize - 1) << 6)));
    result.bytes.insert(result.bytes.end(), path.begin(), path.end());
    result.bytes.insert(result.bytes.end(), payload.begin(), payload.end());
    result.success = true;
    return result;
}

EncodeResult MeshCorePacketEncoder::buildGroupTextPayload(
    const std::string& channelKeyHex,
    const std::string& sender,
    const std::string& message,
    uint32_t timestamp,
    uint8_t flags
) {
    EncodeResult result;
    try {
        auto channelKey16 = hexToBytes(channelKeyHex);
        if (channelKey16.size() != 16) {
            result.error = "channel key must be 16 bytes";
            return result;
        }

        // Plaintext: timestamp(4 LE) + flags(1) + "sender: message"
        std::string text = sender.empty() ? message : sender + ": " + message;
        std::vector<uint8_t> plain;
        plain.reserve(5 + text.size());
        plain.push_back(timestamp & 0xFF);
        plain.push_back((timestamp >> 8) & 0xFF);
        plain.push_back((timestamp >> 16) & 0xFF);
        plain.push_back((timestamp >> 24) & 0xFF);
        plain.push_back(flags);
        plain.insert(plain.end(), text.begin(), text.end());
        // Zero-pad to the AES block; the decoder cuts the text at the first
        // NUL, so the padding is invisible after decryption
        while (plain.size() % 16 != 0) plain.push_back(0);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            result.error = "failed to create cipher context";
            return result;
        }
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, channelKey16.data(), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        std::vector<uint8_t> cipher(plain.size() + 16);
        int outLen = 0, totalLen = 0;
        EVP_EncryptUpdate(ctx, cipher.data(), &outLen, plain.data(),
                          static_cast<int>(plain.size()));
        totalLen = outLen;
        EVP_EncryptFinal_ex(ctx, cipher.data() + totalLen, &outLen);
        totalLen += outLen;
        EVP_CIPHER_CTX_free(ctx);
        cipher.resize(totalLen);

        // MAC: HMAC-SHA256 over the ciphertext with the 32-byte channel
        // secret (16-byte key + 16 zero bytes), truncated to two bytes
        std::vector<uint8_t> channelSecret(32, 0);
        std::copy(channelKey16.begin(), channelKey16.end(), channelSecret.begin());
        unsigned int hmacLen = 0;
        uint8_t mac[EVP_MAX_MD_SIZE];
        HMAC(EVP_sha256(), channelSecret.data(), static_cast<int>(channelSecret.size()),
             cipher.data(), cipher.size(), mac, &hmacLen);

        auto hashHex = ChannelCrypto::calculateChannelHash(channelKeyHex);
        auto hashByte = hexToBytes(hashHex);

        result.bytes.reserve(3 + cipher.size());
        result.bytes.push_back(hashByte[0]);
        result.bytes.push_back(mac[0]);
        result.bytes.push_back(mac[1]);
        result.bytes.insert(result.bytes.end(), cipher.begin(), cipher.end());
        result.success = true;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

EncodeResult MeshCorePacketEncoder::buildAdvertPayload(
    const std::string& privateKeyHex,
    const std::string& publicKeyHex,
    uint32_t timestamp,
    const std::string& name,
    DeviceRole role,
    std::optional<std::pair<double, double>> latLon
) {
    EncodeResult result;
    try {
        auto publicKey = hexToBytes(publicKeyHex);
        if (publicKey.size() != 32) {
            result.error = "public key must be 32 bytes";
            return result;
        }

        // App data: flags [+ lat/lon] [+ name]
        std::vector<uint8_t> appData;
        uint8_t flags = static_cast<uint8_t>(role) & 0x0F;
        if (latLon) flags |= AdvertFlags::HasLocation;
        if (!name.empty()) flags |= AdvertFlags::HasName;
        appData.push_back(flags);
        if (latLon) {
            int32_t lat = static_cast<int32_t>(latLon->first * 1000000.0);
            int32_t lon = static_cast<int32_t>(latLon->second * 1000000.0);
            for (int32_t v : {lat, lon}) {
                appData.push_back(v & 0xFF);
                appData.push_back((v >> 8) & 0xFF);
                appData.push_back((v >> 16) & 0xFF);
                appData.push_back((v >> 24) & 0xFF);
            }
        }
        appData.insert(appData.end(), name.begin(), name.end());

        // Signature over public_key + timestamp(LE) + app_data
        std::vector<uint8_t> signedMessage;
        signedMessage.reserve(32 + 4 + appData.size());
        signedMessage.insert(signedMessage.end(), publicKey.begin(), publicKey.end());
        signedMessage.push_back(timestamp & 0xFF);
        signedMessage.push_back((timestamp >> 8) & 0xFF);
        signedMessage.push_back((timestamp >> 16) & 0xFF);
        signedMessage.push_back((timestamp >> 24) & 0xFF);
        signedMessage.insert(signedMessage.end(), appData.begin(), appData.end());

        auto signatureHex = Ed25519::sign(bytesToHex(signedMessage),
                                          privateKeyHex, publicKeyHex);
        auto signature = hexToBytes(signatureHex);
        if (signature.size() != 64) {
            result.error = "signing produced a non-64-byte signature";
            return result;
        }

        result.bytes.reserve(32 + 4 + 64 + appData.size());
        result.bytes.insert(result.bytes.end(), publicKey.begin(), publicKey.end());
        result.bytes.push_back(timestamp & 0xFF);
        result.bytes.push_back((timestamp >> 8) & 0xFF);
        result.bytes.push_back((timestamp >> 16) & 0xFF);
        result.bytes.push_back((timestamp >> 24) & 0xFF);
        result.bytes.insert(result.bytes.end(), signature.begin(), signature.end());
        result.bytes.insert(result.bytes.end(), appData.begin(), appData.end());
        result.success = true;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

} // namespace meshcore
