# MeshCore Packet Decoder (C++)

C++ implementation of the MeshCore mesh networking packet decoder. Designed to run on any platform with a C++17 compiler and OpenSSL, including Raspberry Pi.

## Features

- Full packet decoding with support for all MeshCore payload types
- GroupText message decryption (AES-128 ECB + HMAC-SHA256)
- Ed25519 signature verification for advertisements
- Ed25519 key derivation and JWT-style auth tokens
- Detailed packet structure analysis
- JSON output mode
- Static library for embedding in other projects

## Supported Payload Types

| Type | Name | Status |
|------|------|--------|
| 0x00 | Request | Decode |
| 0x01 | Response | Decode |
| 0x02 | TextMessage | Decode |
| 0x03 | Ack | Decode |
| 0x04 | Advert | Decode + Signature Verification |
| 0x05 | GroupText | Decode + Decryption |
| 0x07 | AnonRequest | Decode |
| 0x08 | Path | Decode |
| 0x09 | Trace | Decode |
| 0x0B | Control | Decode |

## Dependencies

- **CMake** >= 3.14
- **OpenSSL** (libssl-dev / openssl)
- **nlohmann/json** (fetched automatically by CMake)
- **Google Test** (fetched automatically by CMake, for tests only)

## Building

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### On Raspberry Pi

```bash
sudo apt install cmake libssl-dev
mkdir build && cd build
cmake ..
make -j4
```

### On macOS

```bash
brew install cmake openssl
mkdir build && cd build
cmake -DOPENSSL_ROOT_DIR=$(brew --prefix openssl) ..
make -j$(sysctl -n hw.ncpu)
```

## Usage

### Decode a packet

```bash
./meshcore-decoder 11007E7662676F7F0850...
```

### Decode with channel key for decryption

```bash
./meshcore-decoder decode <hex> -k 8b3387e9c5cdea6ac9e5edbaa115cd72
```

### JSON output

```bash
./meshcore-decoder decode <hex> -j
```

### Show packet structure

```bash
./meshcore-decoder decode <hex> -s
```

### Derive Ed25519 public key

```bash
./meshcore-decoder derive-key <64-byte-private-key-hex>
```

### Generate auth token

```bash
./meshcore-decoder auth-token <public-key> <private-key>
```

### Verify auth token

```bash
./meshcore-decoder verify-token <token>
```

## Running Tests

```bash
cd build
ctest --output-on-failure
```

## Library Usage

```cpp
#include <meshcore/meshcore.h>

int main() {
    auto packet = meshcore::MeshCorePacketDecoder::decode("11007E7662...");

    if (packet.isValid) {
        std::cout << "Route: " << meshcore::getRouteTypeName(packet.routeType) << "\n";
        std::cout << "Type: " << meshcore::getPayloadTypeName(packet.payloadType) << "\n";
    }

    // With decryption
    meshcore::MeshCoreKeyStore keyStore({"8b3387e9c5cdea6ac9e5edbaa115cd72"});
    auto decrypted = meshcore::MeshCorePacketDecoder::decode(hexData, &keyStore);
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

C++ port of [meshcore-decoder](https://github.com/michaelhart/meshcore-decoder) (TypeScript).
