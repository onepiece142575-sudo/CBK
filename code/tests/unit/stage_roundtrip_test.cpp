#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "cbk/stage.h"
#include "src/byte_io.h"
#include "src/stages/password_digest.h"
#include "src/stages/vigenere_stage.h"
#include "src/stages/xor_cbc_stage.h"
#include "src/stages/xor_stage.h"

namespace cbk {
// ensure builtin registration is available
void RegisterBuiltinStages();
}  // namespace cbk

using namespace cbk;

static std::vector<uint8_t> RunProcess(IStage* stage, const std::vector<uint8_t>& input,
                                       size_t chunk) {
    VectorSink sink;
    for (size_t off = 0; off < input.size(); off += chunk) {
        size_t len = std::min(chunk, input.size() - off);
        stage->Process(input.data() + off, len, sink);
    }
    stage->Finish(sink);
    return sink.Buffer();
}

TEST(Stages, RoundTripAll) {
    // register builtin stages so factories are present
    RegisterBuiltinStages();

    std::vector<std::string> names = {"xor", "vigenere", "xor-cbc"};

    std::vector<std::vector<uint8_t>> payloads;
    // empty
    payloads.push_back({});
    // small text (ASCII only to avoid source encoding issues)
    std::string text = "hello, world!";
    payloads.push_back(std::vector<uint8_t>(text.begin(), text.end()));
    // random large
    std::mt19937 rng(12345);
    std::vector<uint8_t> rnd(10000);
    for (size_t i = 0; i < rnd.size(); ++i) rnd[i] = static_cast<uint8_t>(rng() & 0xFF);
    payloads.push_back(rnd);

    const std::string pwd = "P@ssw0rd";

    for (const auto& name : names) {
        SCOPED_TRACE("algorithm=" + name);
        IStageFactory* factory = StageRegistry::Instance().Find(name);
        ASSERT_NE(factory, nullptr);

        for (const auto& payload : payloads) {
            // forward
            auto fwd = factory->CreateForward();
            fwd->SetPassword(pwd);
            std::vector<uint8_t> enc = RunProcess(fwd.get(), payload, 13);

            // inverse
            auto inv = factory->CreateInverse();
            inv->SetPassword(pwd);
            std::vector<uint8_t> dec = RunProcess(inv.get(), enc, 11);

            EXPECT_EQ(payload, dec);
        }
    }
}

TEST(Stages, CbcHandlesIvAndCiphertextInOneCallAndArbitraryChunks) {
    XorCbcStageFactory factory;
    for (size_t size : {0u, 1u, 15u, 16u, 17u, 1024u, 65537u}) {
        const std::vector<uint8_t> plain(size, 42);
        auto encoder = factory.CreateForward();
        encoder->SetPassword("test");
        const auto encoded = RunProcess(encoder.get(), plain, 65536);
        EXPECT_EQ(16 + (size / 16 + 1) * 16, encoded.size());
        for (size_t chunk : {1u, 16u, 31u, 65536u, 100000u}) {
            auto decoder = factory.CreateInverse();
            decoder->SetPassword("test");
            EXPECT_EQ(plain, RunProcess(decoder.get(), encoded, chunk));
        }
    }
}

TEST(Stages, CbcStreamsBeforeFinishAndRejectsTruncationAndBadPadding) {
    XorCbcStageFactory factory;
    auto encoder = factory.CreateForward();
    encoder->SetPassword("test");
    const std::vector<uint8_t> plain(1024, 42);
    const auto encoded = RunProcess(encoder.get(), plain, 65536);
    auto decoder = factory.CreateInverse();
    decoder->SetPassword("test");
    VectorSink sink;
    decoder->Process(encoded.data(), encoded.size(), sink);
    EXPECT_EQ(plain, sink.Buffer());
    decoder->Finish(sink);
    EXPECT_EQ(plain, sink.Buffer());
    for (size_t length : {0u, 15u, 16u, 17u, 1055u}) {
        auto broken = factory.CreateInverse();
        broken->SetPassword("test");
        const std::vector<uint8_t> truncated(encoded.begin(), encoded.begin() + length);
        EXPECT_THROW(RunProcess(broken.get(), truncated, 65536), std::runtime_error);
    }
    auto corrupt = encoded;
    corrupt.back() ^= 1;
    auto broken = factory.CreateInverse();
    broken->SetPassword("test");
    EXPECT_THROW(RunProcess(broken.get(), corrupt, 65536), std::runtime_error);
}

TEST(Stages, CbcDecryptsIndependentLegacyFixture) {
    // Independent CBC recurrence with a fixed IV, including a full padding block.
    const std::string password = "legacy-key";
    std::vector<uint8_t> plain(65536);
    for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint8_t>(i * 37);
    auto padded = plain;
    padded.insert(padded.end(), 16, uint8_t{16});
    std::vector<uint8_t> ciphertext(16, uint8_t{73});
    for (size_t offset = 0; offset < padded.size(); offset += 16) {
        for (size_t i = 0; i < 16; ++i) {
            ciphertext.push_back(static_cast<uint8_t>(
                padded[offset + i] ^ password[i % password.size()] ^ ciphertext[offset + i]));
        }
    }
    for (size_t chunk : {1u, 17u, 65536u, 100000u}) {
        XorCbcStage decoder(true);
        decoder.SetPassword(password);
        EXPECT_EQ(plain, RunProcess(&decoder, ciphertext, chunk));
    }
}

TEST(Stages, MissingPasswordDoesNotAccessInvalidMemory) {
    VectorSink sink;
    const uint8_t byte = 1;
    XorStage xor_stage;
    VigenereStage vigenere;
    EXPECT_THROW(xor_stage.Process(&byte, 1, sink), std::runtime_error);
    EXPECT_THROW(vigenere.Process(&byte, 1, sink), std::runtime_error);
}

TEST(Stages, CbcUsesPasswordSuffixBeyondSixteenBytes) {
    const std::vector<uint8_t> plain(100, 42);
    XorCbcStage encoder;
    encoder.SetPassword("1234567890abcdef-correct");
    const auto encrypted = RunProcess(&encoder, plain, 13);
    XorCbcStage correct(true);
    correct.SetPassword("1234567890abcdef-correct");
    EXPECT_EQ(plain, RunProcess(&correct, encrypted, 11));
    XorCbcStage wrong(true);
    wrong.SetPassword("1234567890abcdef-wrong");
    EXPECT_THROW(RunProcess(&wrong, encrypted, 11), std::runtime_error);
}

TEST(Stages, PasswordDigestMatchesKnownSha256Vectors) {
    const std::vector<std::pair<std::string, std::string>> vectors = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {std::string(1000000, 'a'),
         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}};
    for (const auto& item : vectors) {
        std::string actual;
        for (uint8_t byte : PasswordDigest(item.first)) {
            actual += "0123456789abcdef"[byte >> 4];
            actual += "0123456789abcdef"[byte & 15];
        }
        EXPECT_EQ(item.second, actual);
    }
}
