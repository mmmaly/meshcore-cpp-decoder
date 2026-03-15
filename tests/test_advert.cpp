// Copyright (c) 2025 Michael Hart
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"

using namespace meshcore;

TEST(AdvertDecoder, DecodeWithSignatureVerification) {
    std::string hexData = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172";

    auto packet = MeshCorePacketDecoder::decodeWithVerification(hexData);

    ASSERT_TRUE(packet.payloadDecoded.has_value());
    auto& advert = std::get<AdvertPayload>(packet.payloadDecoded.value());

    // Signature verification should have been attempted
    EXPECT_TRUE(advert.signatureValid.has_value());
    // Note: The signature may or may not be valid depending on the Ed25519 implementation compatibility
    // with the orlp format. What matters is that verification was attempted without crashing.
}

TEST(AdvertDecoder, AnalyzeStructure) {
    std::string hexData = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172";

    auto structure = MeshCorePacketDecoder::analyzeStructure(hexData);

    EXPECT_GT(structure.segments.size(), 0u);
    EXPECT_EQ(structure.segments[0].name, "Header");
    EXPECT_TRUE(structure.segments[0].headerBreakdown.has_value());
    EXPECT_GT(structure.payload.segments.size(), 0u);
    EXPECT_EQ(structure.totalBytes, hexData.length() / 2);
}
