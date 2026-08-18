// Copyright (c) 2026
// MIT License
//
// Peer (direct-message) cryptography: the ECDH shared secret between two
// MeshCore identities and the encrypt-then-MAC cipher keyed by it.
//
// MeshCore derives the secret with orlp/ed25519's ed25519_key_exchange:
// X25519 over the converted keys - the Edwards public point mapped to its
// Montgomery u-coordinate (u = (1+y)/(1-y) mod p) and the private scalar
// taken as the clamped lower half of SHA512(seed). This implementation
// reproduces that with OpenSSL primitives and is validated in tests against
// the reference keypair shipped in the firmware's Identity.cpp.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace meshcore {

class PeerCrypto {
public:
    // Shared secret between our identity (orlp 64-byte private key hex,
    // seed in the first 32 bytes - the format this library uses throughout)
    // and a peer's 32-byte Ed25519 public key. Returns 64 hex chars.
    static std::string keyExchange(const std::string& privateKeyHex,
                                   const std::string& otherPublicKeyHex);

    // Same, but the first argument is the raw 32-byte X25519 scalar (the
    // already-expanded/clamped form orlp stores). Needed for keys captured
    // from devices, and for validating against firmware test vectors.
    static std::string keyExchangeRaw(const std::string& scalarHex,
                                      const std::string& otherPublicKeyHex);

    // Encrypt-then-MAC with a 32-byte secret: AES-128-ECB with the first 16
    // bytes (zero-padded blocks), HMAC-SHA256 keyed with all 32; output is
    // MAC(2) + ciphertext. The channel cipher is this with key16 + zeros.
    static std::vector<uint8_t> encryptThenMac(const std::string& secretHex,
                                               const std::vector<uint8_t>& plain);

    // Verify the 2-byte MAC and decrypt; nullopt when the MAC fails.
    static std::optional<std::vector<uint8_t>> macThenDecrypt(
        const std::string& secretHex, const uint8_t* macAndCipher, size_t len);

    struct DecryptedTextMessage {
        uint32_t timestamp = 0;
        uint8_t txtType = 0;    // flags byte >> 2
        uint8_t attempt = 0;    // flags byte & 3
        std::string text;
    };

    // TXT_MSG payload: dest_hash(1) + src_hash(1) + MAC(2) + ciphertext of
    // [timestamp(4 LE)][(txt_type<<2)|(attempt&3)][text]
    static std::vector<uint8_t> buildTextMessagePayload(
        const std::string& secretHex, uint8_t destHash, uint8_t srcHash,
        uint32_t timestamp, uint8_t attempt, const std::string& text,
        uint8_t txtType = 0);

    // Decrypt a full TXT_MSG payload (dest/src hashes included).
    static std::optional<DecryptedTextMessage> decryptTextMessage(
        const std::string& secretHex, const uint8_t* payload, size_t len);

    // The delivery ACK both sides compute: first 4 bytes (read LE) of
    // SHA256( timestamp(4 LE) || (attempt&3) || text || sender_pub_key(32) )
    static uint32_t calcAckHash(uint32_t timestamp, uint8_t attempt,
                                const std::string& text,
                                const std::string& senderPublicKeyHex);
};

} // namespace meshcore
