// Copyright (c) 2025 Michael Hart
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"

using namespace meshcore;

TEST(GroupTextDecryption, DecryptPublicChannelMessage) {
    std::string hexData = "150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D";

    MeshCoreKeyStore keyStore({"8b3387e9c5cdea6ac9e5edbaa115cd72"});

    auto packet = MeshCorePacketDecoder::decode(hexData, &keyStore);

    EXPECT_TRUE(packet.isValid);
    EXPECT_EQ(packet.routeType, RouteType::Flood);
    EXPECT_EQ(packet.payloadType, PayloadType::GroupText);
    EXPECT_EQ(packet.payloadVersion, PayloadVersion::Version1);

    ASSERT_TRUE(packet.payloadDecoded.has_value());
    auto& groupText = std::get<GroupTextPayload>(packet.payloadDecoded.value());
    EXPECT_TRUE(groupText.isValid);

    EXPECT_EQ(groupText.channelHash, "11");
    EXPECT_EQ(groupText.cipherMac, "C3C1");
    EXPECT_EQ(groupText.ciphertext, "354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D");
    EXPECT_EQ(groupText.ciphertextLength, 32u);

    ASSERT_TRUE(groupText.decrypted.has_value());
    EXPECT_TRUE(groupText.decrypted->sender.has_value());

    // Note: The emoji test depends on proper UTF-8 handling
    // The sender should contain "Tree" and message should be a cloud emoji
    EXPECT_EQ(groupText.decrypted->timestamp, 1758484279u);
}

TEST(GroupTextDecryption, NoKeysProvided) {
    std::string hexData = "150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D";

    auto packet = MeshCorePacketDecoder::decode(hexData);
    auto& groupText = std::get<GroupTextPayload>(packet.payloadDecoded.value());

    EXPECT_EQ(groupText.channelHash, "11");
    EXPECT_FALSE(groupText.decrypted.has_value());
}

TEST(GroupTextDecryption, WrongKey) {
    std::string hexData = "150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D";

    MeshCoreKeyStore keyStore({"wrongkey1234567890abcdef12345678"});

    auto packet = MeshCorePacketDecoder::decode(hexData, &keyStore);
    auto& groupText = std::get<GroupTextPayload>(packet.payloadDecoded.value());

    EXPECT_FALSE(groupText.decrypted.has_value());
}

TEST(GroupTextDecryption, MultipleKeysWithCollision) {
    std::string hexData = "150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D";

    MeshCoreKeyStore keyStore({
        "wrongkey1234567890abcdef12345678",
        "8b3387e9c5cdea6ac9e5edbaa115cd72",
        "anotherwrongkey1234567890abcdef"
    });

    auto packet = MeshCorePacketDecoder::decode(hexData, &keyStore);
    auto& groupText = std::get<GroupTextPayload>(packet.payloadDecoded.value());

    ASSERT_TRUE(groupText.decrypted.has_value());
    EXPECT_EQ(groupText.decrypted->timestamp, 1758484279u);
}
