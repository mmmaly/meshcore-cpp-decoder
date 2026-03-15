// Copyright (c) 2025 Michael Hart
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"

using namespace meshcore;

TEST(TracePacket, DecodeTracePacket) {
    std::string hexData = "260130A24D89BD0000000000FB";

    auto packet = MeshCorePacketDecoder::decode(hexData);

    EXPECT_TRUE(packet.isValid);
    EXPECT_EQ(packet.routeType, RouteType::Direct);
    EXPECT_EQ(packet.payloadType, PayloadType::Trace);
    EXPECT_EQ(packet.payloadVersion, PayloadVersion::Version1);

    ASSERT_TRUE(packet.payloadDecoded.has_value());
    auto& trace = std::get<TracePayload>(packet.payloadDecoded.value());
    EXPECT_TRUE(trace.isValid);

    EXPECT_EQ(trace.traceTag, "BD894DA2");
    EXPECT_EQ(trace.authCode, 0u);
    EXPECT_EQ(trace.flags, 0);
    ASSERT_EQ(trace.pathHashes.size(), 1u);
    EXPECT_EQ(trace.pathHashes[0], "FB");

    // SNR from path: 0x30 = 48, signed = 48, /4 = 12dB
    ASSERT_TRUE(trace.snrValues.has_value());
    ASSERT_EQ(trace.snrValues->size(), 1u);
    EXPECT_DOUBLE_EQ((*trace.snrValues)[0], 12.0);

    EXPECT_EQ(packet.pathLength, 1);
    ASSERT_TRUE(packet.path.has_value());
    ASSERT_EQ(packet.path->size(), 1u);
    EXPECT_EQ((*packet.path)[0], "30");
    EXPECT_EQ(packet.totalBytes, hexData.length() / 2);
}

TEST(TracePacket, InvalidTracePacket) {
    auto packet = MeshCorePacketDecoder::decode("26");
    EXPECT_FALSE(packet.isValid);
}

TEST(TracePacket, ShortTracePayload) {
    std::string hexData = "260100"; // Too short for trace payload
    auto packet = MeshCorePacketDecoder::decode(hexData);
    EXPECT_TRUE(packet.isValid); // Packet structure is valid

    if (packet.payloadDecoded.has_value()) {
        auto& trace = std::get<TracePayload>(packet.payloadDecoded.value());
        EXPECT_FALSE(trace.isValid);
    }
}
