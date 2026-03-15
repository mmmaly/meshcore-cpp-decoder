// MeshCore Packet Decoder CLI - C++ Edition
// Copyright (c) 2025 Michael Hart
// MIT License

#include "meshcore/meshcore.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace meshcore;

// ANSI color codes
namespace color {
    const char* reset = "\033[0m";
    const char* bold = "\033[1m";
    const char* dim = "\033[2m";
    const char* red = "\033[31m";
    const char* green = "\033[32m";
    const char* yellow = "\033[33m";
    const char* cyan = "\033[36m";
}

static std::string cleanHex(const std::string& hex) {
    std::string clean;
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    // Remove 0x prefix
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X')) {
        clean = clean.substr(2);
    }
    return clean;
}

static json payloadToJson(const DecodedPacket& packet) {
    json j;
    j["messageHash"] = packet.messageHash;
    j["routeType"] = static_cast<int>(packet.routeType);
    j["routeTypeName"] = getRouteTypeName(packet.routeType);
    j["payloadType"] = static_cast<int>(packet.payloadType);
    j["payloadTypeName"] = getPayloadTypeName(packet.payloadType);
    j["payloadVersion"] = static_cast<int>(packet.payloadVersion);
    j["pathLength"] = packet.pathLength;
    j["totalBytes"] = packet.totalBytes;
    j["isValid"] = packet.isValid;

    if (packet.transportCodes.has_value()) {
        j["transportCodes"] = {packet.transportCodes->first, packet.transportCodes->second};
    }

    if (packet.path.has_value()) {
        j["path"] = packet.path.value();
    } else {
        j["path"] = nullptr;
    }

    j["payload"]["raw"] = packet.payloadRaw;

    if (!packet.errors.empty()) {
        j["errors"] = packet.errors;
    }

    if (packet.payloadDecoded.has_value()) {
        std::visit([&j](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            json decoded;
            decoded["type"] = static_cast<int>(arg.type);
            decoded["typeName"] = getPayloadTypeName(arg.type);
            decoded["isValid"] = arg.isValid;
            if (!arg.errors.empty()) {
                decoded["errors"] = arg.errors;
            }

            if constexpr (std::is_same_v<T, AdvertPayload>) {
                decoded["publicKey"] = arg.publicKey;
                decoded["timestamp"] = arg.timestamp;
                decoded["signature"] = arg.signature;
                if (arg.signatureValid.has_value()) {
                    decoded["signatureValid"] = arg.signatureValid.value();
                }
                if (arg.signatureError.has_value()) {
                    decoded["signatureError"] = arg.signatureError.value();
                }
                decoded["appData"]["flags"] = arg.appData.flags;
                decoded["appData"]["deviceRole"] = static_cast<int>(arg.appData.deviceRole);
                decoded["appData"]["deviceRoleName"] = getDeviceRoleName(arg.appData.deviceRole);
                decoded["appData"]["hasLocation"] = arg.appData.hasLocation;
                decoded["appData"]["hasName"] = arg.appData.hasName;
                if (arg.appData.latitude.has_value()) {
                    decoded["appData"]["location"]["latitude"] = arg.appData.latitude.value();
                    decoded["appData"]["location"]["longitude"] = arg.appData.longitude.value();
                }
                if (arg.appData.name.has_value()) {
                    decoded["appData"]["name"] = arg.appData.name.value();
                }
            } else if constexpr (std::is_same_v<T, TracePayload>) {
                decoded["traceTag"] = arg.traceTag;
                decoded["authCode"] = arg.authCode;
                decoded["flags"] = arg.flags;
                decoded["pathHashes"] = arg.pathHashes;
                if (arg.snrValues.has_value()) {
                    decoded["snrValues"] = arg.snrValues.value();
                }
            } else if constexpr (std::is_same_v<T, GroupTextPayload>) {
                decoded["channelHash"] = arg.channelHash;
                decoded["cipherMac"] = arg.cipherMac;
                decoded["ciphertext"] = arg.ciphertext;
                decoded["ciphertextLength"] = arg.ciphertextLength;
                if (arg.decrypted.has_value()) {
                    decoded["decrypted"]["timestamp"] = arg.decrypted->timestamp;
                    decoded["decrypted"]["flags"] = arg.decrypted->flags;
                    if (arg.decrypted->sender.has_value()) {
                        decoded["decrypted"]["sender"] = arg.decrypted->sender.value();
                    }
                    decoded["decrypted"]["message"] = arg.decrypted->message;
                }
            } else if constexpr (std::is_same_v<T, RequestPayload>) {
                decoded["destinationHash"] = arg.destinationHash;
                decoded["sourceHash"] = arg.sourceHash;
                decoded["cipherMac"] = arg.cipherMac;
                decoded["ciphertext"] = arg.ciphertext;
            } else if constexpr (std::is_same_v<T, ResponsePayload>) {
                decoded["destinationHash"] = arg.destinationHash;
                decoded["sourceHash"] = arg.sourceHash;
                decoded["cipherMac"] = arg.cipherMac;
                decoded["ciphertext"] = arg.ciphertext;
                decoded["ciphertextLength"] = arg.ciphertextLength;
            } else if constexpr (std::is_same_v<T, TextMessagePayload>) {
                decoded["destinationHash"] = arg.destinationHash;
                decoded["sourceHash"] = arg.sourceHash;
                decoded["cipherMac"] = arg.cipherMac;
                decoded["ciphertext"] = arg.ciphertext;
                decoded["ciphertextLength"] = arg.ciphertextLength;
            } else if constexpr (std::is_same_v<T, AnonRequestPayload>) {
                decoded["destinationHash"] = arg.destinationHash;
                decoded["senderPublicKey"] = arg.senderPublicKey;
                decoded["cipherMac"] = arg.cipherMac;
                decoded["ciphertext"] = arg.ciphertext;
                decoded["ciphertextLength"] = arg.ciphertextLength;
            } else if constexpr (std::is_same_v<T, AckPayload>) {
                decoded["checksum"] = arg.checksum;
            } else if constexpr (std::is_same_v<T, PathPayload>) {
                decoded["pathLength"] = arg.pathLength;
                decoded["pathHashes"] = arg.pathHashes;
                decoded["extraType"] = arg.extraType;
                decoded["extraData"] = arg.extraData;
            } else if constexpr (std::is_same_v<T, ControlDiscoverReqPayload>) {
                decoded["subType"] = "NodeDiscoverReq";
                decoded["rawFlags"] = arg.rawFlags;
                decoded["prefixOnly"] = arg.prefixOnly;
                decoded["typeFilter"] = arg.typeFilter;
                decoded["typeFilterNames"] = arg.typeFilterNames;
                decoded["tag"] = arg.tag;
                decoded["since"] = arg.since;
            } else if constexpr (std::is_same_v<T, ControlDiscoverRespPayload>) {
                decoded["subType"] = "NodeDiscoverResp";
                decoded["rawFlags"] = arg.rawFlags;
                decoded["nodeType"] = static_cast<int>(arg.nodeType);
                decoded["nodeTypeName"] = arg.nodeTypeName;
                decoded["snr"] = arg.snr;
                decoded["tag"] = arg.tag;
                decoded["publicKey"] = arg.publicKey;
                decoded["publicKeyLength"] = arg.publicKeyLength;
            }

            j["payload"]["decoded"] = decoded;
        }, packet.payloadDecoded.value());
    } else {
        j["payload"]["decoded"] = nullptr;
    }

    return j;
}

static void showPayloadDetails(const PayloadData& payload) {
    std::visit([](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_same_v<T, AdvertPayload>) {
            std::cout << color::bold << "Device Role: " << color::reset
                      << getDeviceRoleName(arg.appData.deviceRole) << "\n";
            if (arg.appData.name.has_value()) {
                std::cout << color::bold << "Device Name: " << color::reset
                          << arg.appData.name.value() << "\n";
            }
            if (arg.appData.latitude.has_value()) {
                std::cout << color::bold << "Location: " << color::reset
                          << arg.appData.latitude.value() << ", "
                          << arg.appData.longitude.value() << "\n";
            }
            if (arg.signatureValid.has_value()) {
                if (arg.signatureValid.value()) {
                    std::cout << color::bold << "Signature: " << color::reset
                              << color::green << "Valid Ed25519 signature" << color::reset << "\n";
                } else {
                    std::cout << color::bold << "Signature: " << color::reset
                              << color::red << "Invalid Ed25519 signature" << color::reset << "\n";
                }
            }
        } else if constexpr (std::is_same_v<T, GroupTextPayload>) {
            std::cout << color::bold << "Channel Hash: " << color::reset
                      << arg.channelHash << "\n";
            if (arg.decrypted.has_value()) {
                std::cout << color::green << "Decrypted Message:" << color::reset << "\n";
                if (arg.decrypted->sender.has_value()) {
                    std::cout << color::bold << "Sender: " << color::reset
                              << arg.decrypted->sender.value() << "\n";
                }
                std::cout << color::bold << "Message: " << color::reset
                          << arg.decrypted->message << "\n";
            } else {
                std::cout << color::yellow << "Encrypted (no key available)" << color::reset << "\n";
            }
        } else if constexpr (std::is_same_v<T, TracePayload>) {
            std::cout << color::bold << "Trace Tag: " << color::reset
                      << arg.traceTag << "\n";
            std::cout << color::bold << "Auth Code: " << color::reset
                      << arg.authCode << "\n";
            if (arg.snrValues.has_value() && !arg.snrValues->empty()) {
                std::cout << color::bold << "SNR Values: " << color::reset;
                for (size_t i = 0; i < arg.snrValues->size(); i++) {
                    if (i > 0) std::cout << ", ";
                    std::cout << (*arg.snrValues)[i] << "dB";
                }
                std::cout << "\n";
            }
        } else {
            std::cout << color::bold << "Type: " << color::reset
                      << getPayloadTypeName(arg.type) << "\n";
            std::cout << color::bold << "Valid: " << color::reset
                      << (arg.isValid ? "Yes" : "No") << "\n";
        }
    }, payload);
}

static int cmdDecode(const std::string& hex, const std::vector<std::string>& keys,
                     bool jsonOutput, bool showStructure) {
    std::string cleanedHex = cleanHex(hex);

    MeshCoreKeyStore keyStore;
    if (!keys.empty()) {
        keyStore.addChannelSecrets(keys);
    }

    auto packet = MeshCorePacketDecoder::decodeWithVerification(
        cleanedHex, keys.empty() ? nullptr : &keyStore
    );

    if (jsonOutput) {
        json j = payloadToJson(packet);
        if (showStructure) {
            auto structure = MeshCorePacketDecoder::analyzeStructureWithVerification(
                cleanedHex, keys.empty() ? nullptr : &keyStore
            );
            // Add structure to JSON output
            json sj;
            sj["totalBytes"] = structure.totalBytes;
            sj["rawHex"] = structure.rawHex;
            sj["messageHash"] = structure.messageHash;
            j["structure"] = sj;
        }
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << color::cyan << "=== MeshCore Packet Analysis ===" << color::reset << "\n\n";

        if (!packet.isValid) {
            std::cout << color::red << "Invalid Packet" << color::reset << "\n";
            for (const auto& err : packet.errors) {
                std::cout << color::red << "   " << err << color::reset << "\n";
            }
        } else {
            std::cout << color::green << "Valid Packet" << color::reset << "\n";
        }

        std::cout << color::bold << "Message Hash: " << color::reset << packet.messageHash << "\n";
        std::cout << color::bold << "Route Type: " << color::reset
                  << getRouteTypeName(packet.routeType) << "\n";
        std::cout << color::bold << "Payload Type: " << color::reset
                  << getPayloadTypeName(packet.payloadType) << "\n";
        std::cout << color::bold << "Total Bytes: " << color::reset << packet.totalBytes << "\n";

        if (packet.path.has_value() && !packet.path->empty()) {
            std::cout << color::bold << "Path: " << color::reset;
            for (size_t i = 0; i < packet.path->size(); i++) {
                if (i > 0) std::cout << " -> ";
                std::cout << (*packet.path)[i];
            }
            std::cout << "\n";
        }

        if (packet.payloadDecoded.has_value()) {
            std::cout << color::cyan << "\n=== Payload Details ===" << color::reset << "\n";
            showPayloadDetails(packet.payloadDecoded.value());
        }

        if (showStructure) {
            auto structure = MeshCorePacketDecoder::analyzeStructureWithVerification(
                cleanedHex, keys.empty() ? nullptr : &keyStore
            );

            std::cout << color::cyan << "\n=== Packet Structure ===" << color::reset << "\n";
            std::cout << color::yellow << "\nMain Segments:" << color::reset << "\n";
            for (size_t i = 0; i < structure.segments.size(); i++) {
                const auto& seg = structure.segments[i];
                std::cout << (i + 1) << ". " << color::bold << seg.name << color::reset
                          << " (bytes " << seg.startByte << "-" << seg.endByte << "): "
                          << seg.value << "\n";
                if (!seg.description.empty()) {
                    std::cout << "   " << color::dim << seg.description << color::reset << "\n";
                }
            }

            if (!structure.payload.segments.empty()) {
                std::cout << color::yellow << "\nPayload Segments:" << color::reset << "\n";
                for (size_t i = 0; i < structure.payload.segments.size(); i++) {
                    const auto& seg = structure.payload.segments[i];
                    std::cout << (i + 1) << ". " << color::bold << seg.name << color::reset
                              << " (bytes " << seg.startByte << "-" << seg.endByte << "): "
                              << seg.value << "\n";
                    std::cout << "   " << color::dim << seg.description << color::reset << "\n";
                }
            }
        }

        if (!packet.isValid) return 1;
    }

    return 0;
}

static int cmdDeriveKey(const std::string& privateKeyHex, const std::string& validateKey,
                        bool jsonOutput) {
    std::string cleanKey = cleanHex(privateKeyHex);

    if (cleanKey.length() != 128) {
        std::cerr << color::red << "Error: Private key must be exactly 64 bytes (128 hex characters)"
                  << color::reset << "\n";
        return 1;
    }

    try {
        std::string derivedKey = Ed25519::derivePublicKey(cleanKey);

        if (jsonOutput) {
            json j;
            j["privateKey"] = cleanKey;
            j["derivedPublicKey"] = derivedKey;
            if (!validateKey.empty()) {
                std::string cleanExpected = cleanHex(validateKey);
                j["expectedPublicKey"] = cleanExpected;
                j["isValid"] = Ed25519::validateKeyPair(cleanKey, cleanExpected);
            }
            std::cout << j.dump(2) << "\n";
        } else {
            std::cout << color::cyan << "=== MeshCore Ed25519 Key Derivation ===" << color::reset << "\n\n";
            std::cout << color::bold << "Private Key (64 bytes):" << color::reset << "\n";
            std::cout << color::dim << cleanKey << color::reset << "\n\n";
            std::cout << color::bold << "Derived Public Key (32 bytes):" << color::reset << "\n";
            std::cout << color::green << derivedKey << color::reset << "\n\n";

            if (!validateKey.empty()) {
                std::string cleanExpected = cleanHex(validateKey);
                std::string a = derivedKey, b = cleanExpected;
                std::transform(a.begin(), a.end(), a.begin(), ::toupper);
                std::transform(b.begin(), b.end(), b.begin(), ::toupper);
                bool match = (a == b);
                std::cout << color::bold << "Validation: " << color::reset;
                std::cout << (match ? (std::string(color::green) + "Keys match") :
                                     (std::string(color::red) + "Keys do not match"))
                          << color::reset << "\n";
                if (!match) return 1;
            }

            std::cout << color::green << "Key derivation completed successfully" << color::reset << "\n";
        }
    } catch (const std::exception& e) {
        if (jsonOutput) {
            json j;
            j["error"] = e.what();
            std::cout << j.dump(2) << "\n";
        } else {
            std::cerr << color::red << "Error: " << e.what() << color::reset << "\n";
        }
        return 1;
    }

    return 0;
}

static void printUsage(const char* progName) {
    std::cout << "MeshCore Packet Decoder v0.2.7 (C++)\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << progName << " decode <hex> [options]\n";
    std::cout << "  " << progName << " <hex> [options]           (decode is default)\n";
    std::cout << "  " << progName << " derive-key <private-key> [options]\n";
    std::cout << "  " << progName << " auth-token <public-key> <private-key> [options]\n";
    std::cout << "  " << progName << " verify-token <token> [options]\n\n";
    std::cout << "Decode Options:\n";
    std::cout << "  -k, --key <key>     Channel secret key for decryption (can be repeated)\n";
    std::cout << "  -j, --json          Output as JSON\n";
    std::cout << "  -s, --structure     Show detailed packet structure\n\n";
    std::cout << "Derive-key Options:\n";
    std::cout << "  -v, --validate <key>  Validate against expected public key\n";
    std::cout << "  -j, --json            Output as JSON\n\n";
    std::cout << "Auth-token Options:\n";
    std::cout << "  -e, --exp <seconds>   Token expiration (default: 86400)\n";
    std::cout << "  -c, --claims <json>   Additional claims as JSON\n";
    std::cout << "  -j, --json            Output as JSON\n\n";
    std::cout << "Verify-token Options:\n";
    std::cout << "  -p, --public-key <key>  Expected public key\n";
    std::cout << "  -j, --json              Output as JSON\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    bool jsonOutput = false;
    bool showStructure = false;
    std::vector<std::string> keys;
    std::string validateKey;
    std::string hexArg;
    int expSeconds = 86400;
    std::string claimsJson;
    std::string publicKeyArg;

    // Determine command
    bool isDecodeDefault = false;
    if (command != "decode" && command != "derive-key" &&
        command != "auth-token" && command != "verify-token" &&
        command != "--help" && command != "-h") {
        // Default command is decode
        hexArg = command;
        command = "decode";
        isDecodeDefault = true;
    }

    if (command == "--help" || command == "-h") {
        printUsage(argv[0]);
        return 0;
    }

    // Parse arguments
    int startIdx = isDecodeDefault ? 2 : 2;

    if (command == "decode") {
        if (!isDecodeDefault) {
            if (argc < 3) {
                std::cerr << "Error: hex argument required\n";
                return 1;
            }
            hexArg = argv[2];
            startIdx = 3;
        }

        for (int i = startIdx; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-j" || arg == "--json") {
                jsonOutput = true;
            } else if (arg == "-s" || arg == "--structure") {
                showStructure = true;
            } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
                keys.push_back(argv[++i]);
            }
        }

        return cmdDecode(hexArg, keys, jsonOutput, showStructure);
    }

    if (command == "derive-key") {
        if (argc < 3) {
            std::cerr << "Error: private key argument required\n";
            return 1;
        }
        std::string privKey = argv[2];

        for (int i = 3; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-j" || arg == "--json") {
                jsonOutput = true;
            } else if ((arg == "-v" || arg == "--validate") && i + 1 < argc) {
                validateKey = argv[++i];
            }
        }

        return cmdDeriveKey(privKey, validateKey, jsonOutput);
    }

    if (command == "auth-token") {
        if (argc < 4) {
            std::cerr << "Error: public-key and private-key arguments required\n";
            return 1;
        }
        std::string pubKey = cleanHex(argv[2]);
        std::string privKey = cleanHex(argv[3]);

        for (int i = 4; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-j" || arg == "--json") {
                jsonOutput = true;
            } else if ((arg == "-e" || arg == "--exp") && i + 1 < argc) {
                expSeconds = std::stoi(argv[++i]);
            } else if ((arg == "-c" || arg == "--claims") && i + 1 < argc) {
                claimsJson = argv[++i];
            }
        }

        try {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            AuthTokenPayload payload;
            std::transform(pubKey.begin(), pubKey.end(), pubKey.begin(), ::toupper);
            payload.publicKey = pubKey;
            payload.iat = now;
            payload.exp = now + expSeconds;

            if (!claimsJson.empty()) {
                payload.extraClaims = json::parse(claimsJson);
            }

            std::string token = createAuthToken(payload, privKey, pubKey);

            if (jsonOutput) {
                json j;
                j["token"] = token;
                j["payload"]["publicKey"] = pubKey;
                j["payload"]["iat"] = now;
                j["payload"]["exp"] = now + expSeconds;
                std::cout << j.dump(2) << "\n";
            } else {
                std::cout << token << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << color::red << "Error: " << e.what() << color::reset << "\n";
            return 1;
        }

        return 0;
    }

    if (command == "verify-token") {
        if (argc < 3) {
            std::cerr << "Error: token argument required\n";
            return 1;
        }
        std::string token = argv[2];
        std::string expectedPubKey;

        for (int i = 3; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-j" || arg == "--json") {
                jsonOutput = true;
            } else if ((arg == "-p" || arg == "--public-key") && i + 1 < argc) {
                expectedPubKey = cleanHex(argv[++i]);
                std::transform(expectedPubKey.begin(), expectedPubKey.end(),
                             expectedPubKey.begin(), ::toupper);
            }
        }

        auto result = verifyAuthToken(token, expectedPubKey);

        if (result.has_value()) {
            if (jsonOutput) {
                json j;
                j["valid"] = true;
                j["payload"]["publicKey"] = result->publicKey;
                j["payload"]["iat"] = result->iat;
                if (result->exp.has_value()) {
                    j["payload"]["exp"] = result->exp.value();
                    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                    j["expired"] = now > result->exp.value();
                    j["timeToExpiry"] = result->exp.value() - now;
                }
                std::cout << j.dump(2) << "\n";
            } else {
                std::cout << color::green << "Token is valid" << color::reset << "\n";
                std::cout << "\nPayload:\n";
                std::cout << "  Public Key: " << result->publicKey << "\n";
                std::cout << "  Issued At:  " << result->iat << "\n";
                if (result->exp.has_value()) {
                    std::cout << "  Expires At: " << result->exp.value() << "\n";
                }
            }
        } else {
            if (jsonOutput) {
                json j;
                j["valid"] = false;
                j["error"] = "Token verification failed";
                std::cout << j.dump(2) << "\n";
            } else {
                std::cerr << color::red << "Token verification failed" << color::reset << "\n";
            }
            return 1;
        }

        return 0;
    }

    printUsage(argv[0]);
    return 1;
}
