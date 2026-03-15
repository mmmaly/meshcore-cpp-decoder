cmake_minimum_required(VERSION 3.14)
project(meshcore-decoder VERSION 0.2.7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find nlohmann_json or fetch it
include(FetchContent)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(json)

# Library sources
set(LIB_SOURCES
  src/utils/hex.cpp
  src/utils/enum_names.cpp
  src/types/enums.cpp
  src/crypto/channel_crypto.cpp
  src/crypto/ed25519.cpp
  src/crypto/key_manager.cpp
  src/decoder/payload_decoders/advert.cpp
  src/decoder/payload_decoders/trace.cpp
  src/decoder/payload_decoders/group_text.cpp
  src/decoder/payload_decoders/request.cpp
  src/decoder/payload_decoders/response.cpp
  src/decoder/payload_decoders/text_message.cpp
  src/decoder/payload_decoders/anon_request.cpp
  src/decoder/payload_decoders/ack.cpp
  src/decoder/payload_decoders/path.cpp
  src/decoder/payload_decoders/control.cpp
  src/decoder/packet_decoder.cpp
  src/utils/auth_token.cpp
  src/utils/base64.cpp
)

# Static library
add_library(meshcore_decoder STATIC ${LIB_SOURCES})
target_include_directories(meshcore_decoder PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(meshcore_decoder PUBLIC
  OpenSSL::SSL
  OpenSSL::Crypto
  nlohmann_json::nlohmann_json
)

# CLI executable
add_executable(meshcore-decoder src/cli.cpp)
target_link_libraries(meshcore-decoder PRIVATE meshcore_decoder)

# Install
install(TARGETS meshcore-decoder RUNTIME DESTINATION bin)
install(TARGETS meshcore_decoder ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Tests (optional)
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
  enable_testing()
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(googletest)

  add_executable(meshcore_tests
    tests/test_decode.cpp
    tests/test_grouptext.cpp
    tests/test_trace.cpp
    tests/test_advert.cpp
    tests/test_crypto.cpp
  )
  target_link_libraries(meshcore_tests PRIVATE meshcore_decoder GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(meshcore_tests)
endif()
