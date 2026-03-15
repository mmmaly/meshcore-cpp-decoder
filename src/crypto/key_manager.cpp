// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/crypto/key_manager.h"
#include "meshcore/crypto/channel_crypto.h"
#include <algorithm>

namespace meshcore {

MeshCoreKeyStore::MeshCoreKeyStore(const std::vector<std::string>& channelSecrets) {
    addChannelSecrets(channelSecrets);
}

void MeshCoreKeyStore::addChannelSecrets(const std::vector<std::string>& secretKeys) {
    for (const auto& secretKey : secretKeys) {
        try {
            std::string channelHash = ChannelCrypto::calculateChannelHash(secretKey);
            // Normalize to lowercase
            std::transform(channelHash.begin(), channelHash.end(), channelHash.begin(), ::tolower);
            channelHashToKeys_[channelHash].push_back(secretKey);
        } catch (...) {
            // Skip invalid keys silently (matching TypeScript behavior)
        }
    }
}

void MeshCoreKeyStore::addNodeKey(const std::string& publicKey, const std::string& privateKey) {
    std::string normalized = publicKey;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::toupper);
    nodeKeys_[normalized] = privateKey;
}

bool MeshCoreKeyStore::hasChannelKey(const std::string& channelHash) const {
    std::string normalized = channelHash;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    return channelHashToKeys_.find(normalized) != channelHashToKeys_.end();
}

bool MeshCoreKeyStore::hasNodeKey(const std::string& publicKey) const {
    std::string normalized = publicKey;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::toupper);
    return nodeKeys_.find(normalized) != nodeKeys_.end();
}

std::vector<std::string> MeshCoreKeyStore::getChannelKeys(const std::string& channelHash) const {
    std::string normalized = channelHash;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    auto it = channelHashToKeys_.find(normalized);
    if (it != channelHashToKeys_.end()) {
        return it->second;
    }
    return {};
}

} // namespace meshcore
