// Copyright (c) 2026
// MIT License
//
// Round-trip tests: everything the encoder builds must decode (and verify)
// through the existing decoder, so the two directions cannot drift apart.

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"
#include "meshcore/encoder/packet_encoder.h"

using namespace meshcore;

static const std::string kKey = "8b3387e9c5cdea6ac9e5edbaa115cd72"; // MeshCore public channel

TEST(Encoder, GroupTextRoundTrip) {
    auto payload = MeshCorePacketEncoder::buildGroupTextPayload(
        kKey, "SDRNode", "ahoj svete", 1787080000u, 0);
    ASSERT_TRUE(payload.success) << payload.error;

    auto pkt = MeshCorePacketEncoder::buildPacket(
        RouteType::Flood, PayloadType::GroupText, payload.bytes);
    ASSERT_TRUE(pkt.success) << pkt.error;

    MeshCoreKeyStore keys;
    keys.addChannelSecrets({kKey});
    auto decoded = MeshCorePacketDecoder::decode(bytesToHex(pkt.bytes), &keys);

    EXPECT_EQ(decoded.routeType, RouteType::Flood);
    EXPECT_EQ(decoded.payloadType, PayloadType::GroupText);
    ASSERT_TRUE(decoded.payloadDecoded.has_value());
    auto& gt = std::get<GroupTextPayload>(decoded.payloadDecoded.value());
    ASSERT_TRUE(gt.decrypted.has_value());
    EXPECT_EQ(gt.decrypted->timestamp, 1787080000u);
    ASSERT_TRUE(gt.decrypted->sender.has_value());
    EXPECT_EQ(*gt.decrypted->sender, "SDRNode");
    EXPECT_EQ(gt.decrypted->message, "ahoj svete");
}

TEST(Encoder, GroupTextWrongKeyFailsMac) {
    auto payload = MeshCorePacketEncoder::buildGroupTextPayload(
        kKey, "SDRNode", "tajna sprava", 1787080000u, 0);
    ASSERT_TRUE(payload.success);
    auto res = ChannelCrypto::decryptGroupTextMessage(
        bytesToHex(payload.bytes.data() + 3, payload.bytes.size() - 3),
        bytesToHex(payload.bytes.data() + 1, 2),
        "00112233445566778899aabbccddeeff");
    EXPECT_FALSE(res.success);
}

TEST(Encoder, AdvertRoundTripWithSignature) {
    // orlp/ed25519 64-byte private key format (only the 32-byte seed is used)
    std::string priv = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                       "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    std::string pub = Ed25519::derivePublicKey(priv);
    ASSERT_EQ(pub.size(), 64u);

    auto payload = MeshCorePacketEncoder::buildAdvertPayload(
        priv, pub, 1787080123u, "SDR Node", DeviceRole::ChatNode,
        std::make_pair(48.1486, 17.1077));
    ASSERT_TRUE(payload.success) << payload.error;

    auto pkt = MeshCorePacketEncoder::buildPacket(
        RouteType::Flood, PayloadType::Advert, payload.bytes);
    ASSERT_TRUE(pkt.success);

    auto decoded = MeshCorePacketDecoder::decodeWithVerification(bytesToHex(pkt.bytes));
    ASSERT_TRUE(decoded.payloadDecoded.has_value());
    auto& advert = std::get<AdvertPayload>(decoded.payloadDecoded.value());

    EXPECT_EQ(advert.publicKey, pub);
    EXPECT_EQ(advert.timestamp, 1787080123u);
    ASSERT_TRUE(advert.appData.name.has_value());
    EXPECT_EQ(*advert.appData.name, "SDR Node");
    EXPECT_EQ(advert.appData.deviceRole, DeviceRole::ChatNode);
    ASSERT_TRUE(advert.appData.latitude.has_value());
    EXPECT_NEAR(*advert.appData.latitude, 48.1486, 0.000001);
    EXPECT_NEAR(*advert.appData.longitude, 17.1077, 0.000001);
    ASSERT_TRUE(advert.signatureValid.has_value());
    EXPECT_TRUE(*advert.signatureValid);
}

TEST(Encoder, PacketWithPathRoundTrip) {
    std::vector<uint8_t> payload = {0xde, 0xad, 0xbe, 0xef};
    std::vector<uint8_t> path = {0x11, 0x22, 0x33};
    auto pkt = MeshCorePacketEncoder::buildPacket(
        RouteType::Direct, PayloadType::RawCustom, payload, path, 1);
    ASSERT_TRUE(pkt.success);

    auto decoded = MeshCorePacketDecoder::decode(bytesToHex(pkt.bytes));
    EXPECT_EQ(decoded.routeType, RouteType::Direct);
    EXPECT_EQ(decoded.pathLength, 3);
    ASSERT_TRUE(decoded.path.has_value());
    EXPECT_EQ((*decoded.path)[0], "11");
    EXPECT_EQ((*decoded.path)[2], "33");
    EXPECT_EQ(decoded.payloadRaw, "DEADBEEF");
}

TEST(Encoder, TransportCodesRoundTrip) {
    std::vector<uint8_t> payload = {0x01, 0x02};
    auto pkt = MeshCorePacketEncoder::buildPacket(
        RouteType::TransportFlood, PayloadType::RawCustom, payload, {}, 1,
        std::make_pair<uint16_t, uint16_t>(0x1234, 0xabcd));
    ASSERT_TRUE(pkt.success);

    auto decoded = MeshCorePacketDecoder::decode(bytesToHex(pkt.bytes));
    ASSERT_TRUE(decoded.transportCodes.has_value());
    EXPECT_EQ(decoded.transportCodes->first, 0x1234);
    EXPECT_EQ(decoded.transportCodes->second, 0xabcd);
}
