// Copyright (c) 2026
// MIT License

#include <gtest/gtest.h>
#include "meshcore/meshcore.h"
#include "meshcore/crypto/peer_crypto.h"

using namespace meshcore;

// Reference keypair from the firmware's Identity.cpp (validatePrivateKey):
// an orlp expanded private key (X25519 scalar in the first 32 bytes) and
// its Ed25519 public key. If our ECDH agrees with itself across both key
// formats against this pair, it agrees with the firmware.
static const std::string kRefPrv =
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471";
static const std::string kRefPub =
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10";

TEST(PeerCrypto, SharedSecretMatchesAcrossKeyFormats) {
    std::string seed = "2222222222222222222222222222222222222222222222222222222222222222";
    std::string myPub = Ed25519::derivePublicKey(seed + seed);

    // us (seed format) with their public key
    std::string ss1 = PeerCrypto::keyExchange(seed + seed, kRefPub);
    // them (expanded orlp scalar) with our public key
    std::string ss2 = PeerCrypto::keyExchangeRaw(kRefPrv.substr(0, 64), myPub);

    EXPECT_EQ(ss1, ss2);
    EXPECT_EQ(ss1.size(), 64u);
    EXPECT_NE(ss1, std::string(64, '0'));
}

TEST(PeerCrypto, TextMessageRoundTrip) {
    std::string seedA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::string seedB = "abababababababababababababababababababababababababababababababab";
    std::string pubA = Ed25519::derivePublicKey(seedA + seedA);
    std::string pubB = Ed25519::derivePublicKey(seedB + seedB);

    std::string ssA = PeerCrypto::keyExchange(seedA + seedA, pubB);
    std::string ssB = PeerCrypto::keyExchange(seedB + seedB, pubA);
    ASSERT_EQ(ssA, ssB);   // ECDH symmetry with fresh keys

    auto payload = PeerCrypto::buildTextMessagePayload(
        ssA, 0x2E, 0x1E, 1787100000u, 1, "ahoj, sukromna sprava");
    EXPECT_EQ(payload[0], 0x2E);
    EXPECT_EQ(payload[1], 0x1E);

    auto msg = PeerCrypto::decryptTextMessage(ssB, payload.data(), payload.size());
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->timestamp, 1787100000u);
    EXPECT_EQ(msg->txtType, 0);
    EXPECT_EQ(msg->attempt, 1);
    EXPECT_EQ(msg->text, "ahoj, sukromna sprava");
}

TEST(PeerCrypto, WrongSecretFailsMac) {
    std::string good(64, 'a');
    std::string bad(64, 'b');
    auto payload = PeerCrypto::buildTextMessagePayload(
        good, 0x01, 0x02, 1787100000u, 0, "tajne");
    EXPECT_FALSE(PeerCrypto::decryptTextMessage(bad, payload.data(), payload.size()).has_value());
    EXPECT_TRUE(PeerCrypto::decryptTextMessage(good, payload.data(), payload.size()).has_value());
}

TEST(PeerCrypto, AckHashDeterministic) {
    // Sender computes the expected ack from its own pubkey; the receiver
    // computes the same value from the decrypted fields + sender pubkey.
    uint32_t a1 = PeerCrypto::calcAckHash(1787100000u, 2, "ahoj", kRefPub);
    uint32_t a2 = PeerCrypto::calcAckHash(1787100000u, 2, "ahoj", kRefPub);
    uint32_t a3 = PeerCrypto::calcAckHash(1787100001u, 2, "ahoj", kRefPub);
    EXPECT_EQ(a1, a2);
    EXPECT_NE(a1, a3);
    EXPECT_NE(a1, 0u);
}
