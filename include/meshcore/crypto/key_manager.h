// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include <vector>
#include <map>

namespace meshcore {

class MeshCoreKeyStore {
public:
    MeshCoreKeyStore() = default;
    MeshCoreKeyStore(const std::vector<std::string>& channelSecrets);

    void addChannelSecrets(const std::vector<std::string>& secretKeys);
    void addNodeKey(const std::string& publicKey, const std::string& privateKey);

    bool hasChannelKey(const std::string& channelHash) const;
    bool hasNodeKey(const std::string& publicKey) const;
    std::vector<std::string> getChannelKeys(const std::string& channelHash) const;

private:
    std::map<std::string, std::vector<std::string>> channelHashToKeys_;
    std::map<std::string, std::string> nodeKeys_;
};

} // namespace meshcore
