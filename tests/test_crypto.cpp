// Copyright (c) 2025 Michael Hart
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"

using namespace meshcore;

TEST(ChannelCrypto, CalculateChannelHash) {
    std::string hash = ChannelCrypto::calculateChannelHash("8b3387e9c5cdea6ac9e5edbaa115cd72");
    // The hash should be a 2-character hex string (1 byte)
    EXPECT_EQ(hash.length(), 2u);
    // Based on the TypeScript test, hash of this key should be "11"
    std::string normalized = hash;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    EXPECT_EQ(normalized, "11");
}

TEST(HexUtils, ByteToHex) {
    EXPECT_EQ(byteToHex(0x00), "00");
    EXPECT_EQ(byteToHex(0xFF), "FF");
    EXPECT_EQ(byteToHex(0xAB), "AB");
}

TEST(HexUtils, HexToBytes) {
    auto bytes = hexToBytes("AABB");
    ASSERT_EQ(bytes.size(), 2u);
    EXPECT_EQ(bytes[0], 0xAA);
    EXPECT_EQ(bytes[1], 0xBB);
}

TEST(HexUtils, HexToBytesInvalid) {
    EXPECT_THROW(hexToBytes("GG"), std::runtime_error);
    EXPECT_THROW(hexToBytes("A"), std::runtime_error);
}

TEST(HexUtils, RoundTrip) {
    std::string original = "DEADBEEF";
    auto bytes = hexToBytes(original);
    std::string result = bytesToHex(bytes);
    EXPECT_EQ(result, original);
}

TEST(KeyManager, BasicOperations) {
    MeshCoreKeyStore store;
    store.addChannelSecrets({"8b3387e9c5cdea6ac9e5edbaa115cd72"});

    EXPECT_TRUE(store.hasChannelKey("11"));
    EXPECT_FALSE(store.hasChannelKey("22"));

    auto keys = store.getChannelKeys("11");
    ASSERT_EQ(keys.size(), 1u);
    EXPECT_EQ(keys[0], "8b3387e9c5cdea6ac9e5edbaa115cd72");
}
