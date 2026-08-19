// Copyright (c) 2026
// MIT License

#include "meshcore/crypto/peer_crypto.h"
#include "meshcore/utils/hex.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <stdexcept>

namespace meshcore {

// Map an Ed25519 public key (compressed Edwards point, little-endian y with
// the x-sign in the top bit) to the corresponding Montgomery u-coordinate:
// u = (1 + y) / (1 - y) mod 2^255 - 19. This is exactly what orlp's
// ed25519_key_exchange does before its curve25519 ladder.
static std::vector<uint8_t> edwardsToMontgomery(const std::vector<uint8_t>& edPub) {
    if (edPub.size() != 32) throw std::runtime_error("public key must be 32 bytes");
    std::vector<uint8_t> yBytes = edPub;
    yBytes[31] &= 0x7F;   // clear the x sign bit; u depends only on y

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* y = BN_lebin2bn(yBytes.data(), 32, nullptr);
    BIGNUM* num = BN_new();
    BIGNUM* den = BN_new();
    BIGNUM* u = BN_new();
    // p = 2^255 - 19
    BN_set_bit(p, 255);
    BN_sub_word(p, 19);

    std::vector<uint8_t> out(32);
    bool ok = false;
    if (ctx && p && y && num && den && u && BN_cmp(y, p) < 0) {
        BN_one(num);
        BN_mod_add(num, num, y, p, ctx);          // 1 + y
        BN_one(den);
        BN_mod_sub(den, den, y, p, ctx);          // 1 - y
        if (!BN_is_zero(den) &&
            BN_mod_inverse(den, den, p, ctx) &&
            BN_mod_mul(u, num, den, p, ctx) &&
            BN_bn2lebinpad(u, out.data(), 32) == 32) {
            ok = true;
        }
    }
    BN_free(p); BN_free(y); BN_free(num); BN_free(den); BN_free(u);
    BN_CTX_free(ctx);
    if (!ok) throw std::runtime_error("invalid Ed25519 point");
    return out;
}

std::string PeerCrypto::keyExchangeRaw(const std::string& scalarHex,
                                       const std::string& otherPublicKeyHex) {
    auto scalar = hexToBytes(scalarHex);
    if (scalar.size() < 32) throw std::runtime_error("scalar must be 32 bytes");
    auto u = edwardsToMontgomery(hexToBytes(otherPublicKeyHex));

    // X25519 clamps the scalar on use (RFC 7748), identically to orlp's
    // keypair generation, so passing an already-clamped scalar is a no-op.
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                  scalar.data(), 32);
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                u.data(), 32);
    uint8_t secret[32];
    size_t secretLen = sizeof(secret);
    bool ok = false;
    if (priv && pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
        if (ctx &&
            EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, pub) == 1 &&
            EVP_PKEY_derive(ctx, secret, &secretLen) == 1 && secretLen == 32) {
            ok = true;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    if (!ok) throw std::runtime_error("X25519 derive failed");
    return bytesToHex(secret, 32);
}

std::string PeerCrypto::keyExchange(const std::string& privateKeyHex,
                                    const std::string& otherPublicKeyHex) {
    auto priv = hexToBytes(privateKeyHex);
    if (priv.size() != 64) throw std::runtime_error("private key must be 64 bytes");
    // This library's convention keeps the seed in the first 32 bytes; the
    // DH scalar is the clamped lower half of SHA512(seed), exactly what
    // orlp's ed25519_create_keypair stores as its expanded private key.
    uint8_t h[SHA512_DIGEST_LENGTH];
    SHA512(priv.data(), 32, h);
    return keyExchangeRaw(bytesToHex(h, 32), otherPublicKeyHex);
}

std::vector<uint8_t> PeerCrypto::encryptThenMac(const std::string& secretHex,
                                                const std::vector<uint8_t>& plain) {
    auto secret = hexToBytes(secretHex);
    if (secret.size() != 32) throw std::runtime_error("secret must be 32 bytes");

    std::vector<uint8_t> padded = plain;
    while (padded.size() % 16 != 0) padded.push_back(0);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher context");
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, secret.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    std::vector<uint8_t> cipher(padded.size() + 16);
    int outLen = 0, total = 0;
    EVP_EncryptUpdate(ctx, cipher.data(), &outLen, padded.data(), (int)padded.size());
    total = outLen;
    EVP_EncryptFinal_ex(ctx, cipher.data() + total, &outLen);
    total += outLen;
    EVP_CIPHER_CTX_free(ctx);
    cipher.resize(total);

    unsigned int macLen = 0;
    uint8_t mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), secret.data(), 32, cipher.data(), cipher.size(), mac, &macLen);

    std::vector<uint8_t> out;
    out.reserve(2 + cipher.size());
    out.push_back(mac[0]);
    out.push_back(mac[1]);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return out;
}

std::optional<std::vector<uint8_t>> PeerCrypto::macThenDecrypt(
    const std::string& secretHex, const uint8_t* macAndCipher, size_t len) {
    auto secret = hexToBytes(secretHex);
    if (secret.size() != 32 || len <= 2) return std::nullopt;

    unsigned int macLen = 0;
    uint8_t mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), secret.data(), 32, macAndCipher + 2, len - 2, mac, &macLen);
    if (mac[0] != macAndCipher[0] || mac[1] != macAndCipher[1]) return std::nullopt;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, secret.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    std::vector<uint8_t> plain(len - 2 + 16);
    int outLen = 0, total = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &outLen, macAndCipher + 2, (int)(len - 2));
    total = outLen;
    EVP_DecryptFinal_ex(ctx, plain.data() + total, &outLen);
    total += outLen;
    EVP_CIPHER_CTX_free(ctx);
    plain.resize(total);
    return plain;
}

std::vector<uint8_t> PeerCrypto::buildTextMessagePayload(
    const std::string& secretHex, uint8_t destHash, uint8_t srcHash,
    uint32_t timestamp, uint8_t attempt, const std::string& text, uint8_t txtType) {
    std::vector<uint8_t> plain;
    plain.reserve(5 + text.size());
    plain.push_back(timestamp & 0xFF);
    plain.push_back((timestamp >> 8) & 0xFF);
    plain.push_back((timestamp >> 16) & 0xFF);
    plain.push_back((timestamp >> 24) & 0xFF);
    plain.push_back((uint8_t)((txtType << 2) | (attempt & 3)));
    plain.insert(plain.end(), text.begin(), text.end());

    auto macAndCipher = encryptThenMac(secretHex, plain);
    std::vector<uint8_t> payload;
    payload.reserve(2 + macAndCipher.size());
    payload.push_back(destHash);
    payload.push_back(srcHash);
    payload.insert(payload.end(), macAndCipher.begin(), macAndCipher.end());
    return payload;
}

std::optional<PeerCrypto::DecryptedTextMessage> PeerCrypto::decryptTextMessage(
    const std::string& secretHex, const uint8_t* payload, size_t len) {
    if (len < 2 + 2 + 16) return std::nullopt;
    auto plain = macThenDecrypt(secretHex, payload + 2, len - 2);
    if (!plain || plain->size() < 5) return std::nullopt;

    DecryptedTextMessage msg;
    msg.timestamp = (uint32_t)(*plain)[0] | ((uint32_t)(*plain)[1] << 8) |
                    ((uint32_t)(*plain)[2] << 16) | ((uint32_t)(*plain)[3] << 24);
    msg.txtType = (*plain)[4] >> 2;
    msg.attempt = (*plain)[4] & 3;
    std::string text(plain->begin() + 5, plain->end());
    auto nul = text.find('\0');
    if (nul != std::string::npos) text.resize(nul);
    msg.text = text;
    return msg;
}

uint32_t PeerCrypto::calcAckHash(uint32_t timestamp, uint8_t attempt,
                                 const std::string& text,
                                 const std::string& senderPublicKeyHex) {
    auto pub = hexToBytes(senderPublicKeyHex);
    std::vector<uint8_t> buf;
    buf.reserve(5 + text.size() + pub.size());
    buf.push_back(timestamp & 0xFF);
    buf.push_back((timestamp >> 8) & 0xFF);
    buf.push_back((timestamp >> 16) & 0xFF);
    buf.push_back((timestamp >> 24) & 0xFF);
    buf.push_back((uint8_t)(attempt & 3));
    buf.insert(buf.end(), text.begin(), text.end());
    buf.insert(buf.end(), pub.begin(), pub.end());

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), hash);
    return (uint32_t)hash[0] | ((uint32_t)hash[1] << 8) |
           ((uint32_t)hash[2] << 16) | ((uint32_t)hash[3] << 24);
}

} // namespace meshcore
