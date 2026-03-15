// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/decoder/payload_decoders/group_text.h"
#include "meshcore/crypto/channel_crypto.h"
#include "meshcore/utils/hex.h"

namespace meshcore {

GroupTextPayload GroupTextPayloadDecoder::decode(const uint8_t* payload, size_t len,
                                                 const MeshCoreKeyStore* keyStore) {
    GroupTextPayload groupText;
    groupText.type = PayloadType::GroupText;
    groupText.version = PayloadVersion::Version1;

    if (len < 3) {
        groupText.isValid = false;
        groupText.errors.push_back("GroupText payload too short");
        return groupText;
    }

    try {
        size_t offset = 0;

        groupText.channelHash = byteToHex(payload[offset]);
        offset += 1;

        groupText.cipherMac = bytesToHex(payload + offset, 2);
        offset += 2;

        groupText.ciphertext = bytesToHex(payload + offset, len - offset);
        groupText.ciphertextLength = len - 3;

        // Attempt decryption if key store is provided
        if (keyStore && keyStore->hasChannelKey(groupText.channelHash)) {
            auto channelKeys = keyStore->getChannelKeys(groupText.channelHash);
            for (const auto& channelKey : channelKeys) {
                auto result = ChannelCrypto::decryptGroupTextMessage(
                    groupText.ciphertext, groupText.cipherMac, channelKey
                );
                if (result.success) {
                    GroupTextDecrypted decrypted;
                    decrypted.timestamp = result.timestamp;
                    decrypted.flags = result.flags;
                    decrypted.sender = result.sender;
                    decrypted.message = result.message;
                    groupText.decrypted = decrypted;
                    break;
                }
            }
        }

        groupText.isValid = true;
    } catch (const std::exception& e) {
        groupText.isValid = false;
        groupText.errors.push_back(e.what());
    }

    return groupText;
}

std::vector<PayloadSegment> GroupTextPayloadDecoder::generateSegments(const uint8_t* payload, size_t len, int segmentOffset) {
    std::vector<PayloadSegment> segments;
    if (len < 3) {
        segments.push_back({"Invalid GroupText Data", "GroupText payload too short",
                           segmentOffset, segmentOffset + static_cast<int>(len) - 1, bytesToHex(payload, len)});
        return segments;
    }

    int offset = 0;

    segments.push_back({"Channel Hash", "First byte of SHA256 of channel's shared key",
                        segmentOffset + offset, segmentOffset + offset,
                        byteToHex(payload[offset])});
    offset += 1;

    segments.push_back({"Cipher MAC", "MAC for encrypted data",
                        segmentOffset + offset, segmentOffset + offset + 1,
                        bytesToHex(payload + offset, 2)});
    offset += 2;

    if (len > static_cast<size_t>(offset)) {
        segments.push_back({"Ciphertext", "Encrypted message content",
                            segmentOffset + offset, segmentOffset + static_cast<int>(len) - 1,
                            bytesToHex(payload + offset, len - offset)});
    }

    return segments;
}

} // namespace meshcore
