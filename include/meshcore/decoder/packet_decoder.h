// Copyright (c) 2025 Michael Hart
// MIT License

#pragma once

#include <string>
#include "../types/packet.h"
#include "../crypto/key_manager.h"

namespace meshcore {

class MeshCorePacketDecoder {
public:
    static DecodedPacket decode(const std::string& hexData,
                                const MeshCoreKeyStore* keyStore = nullptr);

    static DecodedPacket decodeWithVerification(const std::string& hexData,
                                                const MeshCoreKeyStore* keyStore = nullptr);

    static PacketStructure analyzeStructure(const std::string& hexData,
                                            const MeshCoreKeyStore* keyStore = nullptr);

    static PacketStructure analyzeStructureWithVerification(const std::string& hexData,
                                                            const MeshCoreKeyStore* keyStore = nullptr);

    static ValidationResult validate(const std::string& hexData);

    static std::string calculateMessageHash(const uint8_t* bytes, size_t len,
                                            uint8_t routeType, uint8_t payloadType,
                                            uint8_t payloadVersion);
};

} // namespace meshcore
