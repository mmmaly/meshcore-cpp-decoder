// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/crypto/channel_crypto.h"
#include "meshcore/utils/hex.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <algorithm>

namespace meshcore {

DecryptionResult ChannelCrypto::decryptGroupTextMessage(
    const std::string& ciphertextHex,
    const std::string& cipherMacHex,
    const std::string& channelKeyHex
) {
    DecryptionResult result;
    try {
        auto channelKey16 = hexToBytes(channelKeyHex);
        auto macBytes = hexToBytes(cipherMacHex);
        auto ciphertextBytes = hexToBytes(ciphertextHex);

        // MeshCore uses 32-byte channel secret: 16-byte key + 16 zero bytes
        std::vector<uint8_t> channelSecret(32, 0);
        std::copy(channelKey16.begin(), channelKey16.end(), channelSecret.begin());

        // Step 1: Verify HMAC-SHA256 using full 32-byte channel secret
        unsigned int hmacLen = 0;
        uint8_t hmacResult[EVP_MAX_MD_SIZE];
        HMAC(EVP_sha256(),
             channelSecret.data(), static_cast<int>(channelSecret.size()),
             ciphertextBytes.data(), ciphertextBytes.size(),
             hmacResult, &hmacLen);

        if (hmacResult[0] != macBytes[0] || hmacResult[1] != macBytes[1]) {
            result.error = "MAC verification failed";
            return result;
        }

        // Step 2: Decrypt using AES-128 ECB with first 16 bytes of channel secret
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            result.error = "Failed to create cipher context";
            return result;
        }

        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, channelKey16.data(), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding

        std::vector<uint8_t> decryptedBytes(ciphertextBytes.size() + 16);
        int outLen = 0;
        int totalLen = 0;

        EVP_DecryptUpdate(ctx, decryptedBytes.data(), &outLen,
                          ciphertextBytes.data(), static_cast<int>(ciphertextBytes.size()));
        totalLen = outLen;

        EVP_DecryptFinal_ex(ctx, decryptedBytes.data() + totalLen, &outLen);
        totalLen += outLen;
        EVP_CIPHER_CTX_free(ctx);

        decryptedBytes.resize(totalLen);

        if (decryptedBytes.size() < 5) {
            result.error = "Decrypted content too short";
            return result;
        }

        // Parse MeshCore format: timestamp(4) + flags(1) + message_text
        result.timestamp = static_cast<uint32_t>(decryptedBytes[0]) |
                          (static_cast<uint32_t>(decryptedBytes[1]) << 8) |
                          (static_cast<uint32_t>(decryptedBytes[2]) << 16) |
                          (static_cast<uint32_t>(decryptedBytes[3]) << 24);

        result.flags = decryptedBytes[4];

        // Extract message text (UTF-8)
        std::string messageText(decryptedBytes.begin() + 5, decryptedBytes.end());

        // Remove null terminator if present
        auto nullPos = messageText.find('\0');
        if (nullPos != std::string::npos) {
            messageText = messageText.substr(0, nullPos);
        }

        // Parse sender and message (format: "sender: message")
        auto colonPos = messageText.find(": ");
        if (colonPos != std::string::npos && colonPos > 0 && colonPos < 50) {
            std::string potentialSender = messageText.substr(0, colonPos);
            if (potentialSender.find(':') == std::string::npos &&
                potentialSender.find('[') == std::string::npos &&
                potentialSender.find(']') == std::string::npos) {
                result.sender = potentialSender;
                messageText = messageText.substr(colonPos + 2);
            }
        }

        result.message = messageText;
        result.success = true;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

std::string ChannelCrypto::calculateChannelHash(const std::string& secretKeyHex) {
    auto secretBytes = hexToBytes(secretKeyHex);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(secretBytes.data(), secretBytes.size(), hash);

    return byteToHex(hash[0]);
}

} // namespace meshcore
