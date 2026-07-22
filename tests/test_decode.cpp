// Copyright (c) 2025 Michael Hart
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"

using namespace meshcore;

TEST(PacketDecoder, DecodeAdvertPacket) {
    std::string hexData = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172";

    auto packet = MeshCorePacketDecoder::decode(hexData);

    EXPECT_TRUE(packet.isValid);
    EXPECT_EQ(packet.routeType, RouteType::Flood);
    EXPECT_EQ(packet.payloadType, PayloadType::Advert);
    EXPECT_EQ(packet.payloadVersion, PayloadVersion::Version1);
    EXPECT_EQ(packet.pathLength, 0);
    EXPECT_FALSE(packet.path.has_value());
    EXPECT_EQ(packet.totalBytes, hexData.length() / 2);
}

TEST(PacketDecoder, DecodeAdvertPayloadFields) {
    std::string hexData = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172";

    auto packet = MeshCorePacketDecoder::decode(hexData);
    ASSERT_TRUE(packet.payloadDecoded.has_value());

    auto& advert = std::get<AdvertPayload>(packet.payloadDecoded.value());
    EXPECT_TRUE(advert.isValid);
    EXPECT_EQ(advert.publicKey, "7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400");
    EXPECT_EQ(advert.timestamp, 1758455660u);
    EXPECT_EQ(advert.appData.deviceRole, DeviceRole::Repeater);
    EXPECT_TRUE(advert.appData.hasName);
    EXPECT_TRUE(advert.appData.hasLocation);
    EXPECT_EQ(advert.appData.name.value(), "WW7STR/PugetMesh Cougar");
    EXPECT_NEAR(advert.appData.latitude.value(), 47.543968, 0.000001);
    EXPECT_NEAR(advert.appData.longitude.value(), -122.108616, 0.000001);
}

TEST(PacketDecoder, InvalidPacketTooShort) {
    auto packet = MeshCorePacketDecoder::decode("11");

    EXPECT_FALSE(packet.isValid);
    EXPECT_FALSE(packet.errors.empty());
}

TEST(PacketDecoder, ValidatePacket) {
    std::string hexData = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172";

    auto validation = MeshCorePacketDecoder::validate(hexData);
    EXPECT_TRUE(validation.isValid);
    EXPECT_TRUE(validation.errors.empty());
}

TEST(PacketDecoder, CreateKeyStore) {
    MeshCoreKeyStore keyStore({"8b3387e9c5cdea6ac9e5edbaa115cd72"});

    EXPECT_TRUE(keyStore.hasChannelKey("11"));
    EXPECT_FALSE(keyStore.hasChannelKey("22"));
}

TEST(PacketDecoder, DecodeMultiBytePathHashes) {
    // path_len byte encodes hash size in bits 6-7 (Packet.h upstream):
    // 0x42 = 2 hops x 2-byte hashes. Payload is a minimal Path payload
    // (0 hops, extraType 0xFF).
    std::string hexData = "2142AABBCCDD00FF";

    auto packet = MeshCorePacketDecoder::decode(hexData);

    EXPECT_TRUE(packet.isValid);
    EXPECT_EQ(packet.routeType, RouteType::Flood);
    EXPECT_EQ(packet.payloadType, PayloadType::Path);
    EXPECT_EQ(packet.pathLength, 2);
    ASSERT_TRUE(packet.path.has_value());
    ASSERT_EQ(packet.path->size(), 2u);
    EXPECT_EQ((*packet.path)[0], "AABB");
    EXPECT_EQ((*packet.path)[1], "CCDD");
}

TEST(PacketDecoder, DecodeSingleBytePathHashesUnchanged) {
    // Legacy 1-byte hashes: path_len byte < 64 is a plain hop count
    std::string hexData = "2102AABB00FF";

    auto packet = MeshCorePacketDecoder::decode(hexData);

    EXPECT_TRUE(packet.isValid);
    EXPECT_EQ(packet.pathLength, 2);
    ASSERT_TRUE(packet.path.has_value());
    ASSERT_EQ(packet.path->size(), 2u);
    EXPECT_EQ((*packet.path)[0], "AA");
    EXPECT_EQ((*packet.path)[1], "BB");
}
