// Copyright 2026 CBK Project.
#include "src/stages/password_digest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace cbk {
namespace {

constexpr std::array<uint32_t, 64> kRoundConstants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t RotateRight(uint32_t value, unsigned int shift) {
    return (value >> shift) | (value << (32 - shift));
}

void Compress(const std::array<uint8_t, 64>& block, std::array<uint32_t, 8>* state) {
    std::array<uint32_t, 64> words{};
    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 4; ++j) words[i] = (words[i] << 8) | block[i * 4 + j];
    }
    for (size_t i = 16; i < words.size(); ++i) {
        const uint32_t x = words[i - 15];
        const uint32_t y = words[i - 2];
        words[i] = words[i - 16] + (RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3)) +
                   words[i - 7] + (RotateRight(y, 17) ^ RotateRight(y, 19) ^ (y >> 10));
    }
    auto work = *state;
    for (size_t i = 0; i < words.size(); ++i) {
        const uint32_t sum1 =
            RotateRight(work[4], 6) ^ RotateRight(work[4], 11) ^ RotateRight(work[4], 25);
        const uint32_t choose = (work[4] & work[5]) ^ (~work[4] & work[6]);
        const uint32_t temp1 = work[7] + sum1 + choose + kRoundConstants[i] + words[i];
        const uint32_t sum0 =
            RotateRight(work[0], 2) ^ RotateRight(work[0], 13) ^ RotateRight(work[0], 22);
        const uint32_t majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
        for (size_t j = 7; j > 0; --j) work[j] = work[j - 1];
        work[4] += temp1;
        work[0] = temp1 + sum0 + majority;
    }
    for (size_t i = 0; i < state->size(); ++i) (*state)[i] += work[i];
}

}  // namespace

std::array<uint8_t, 32> PasswordDigest(const std::string& password) {
    std::array<uint32_t, 8> state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::array<uint8_t, 64> block{};
    size_t used = 0;
    for (unsigned char byte : password) {
        block[used++] = byte;
        if (used == block.size()) {
            Compress(block, &state);
            used = 0;
            block.fill(0);
        }
    }
    // The final 64 bits hold the original message length in big-endian bits.
    block[used++] = 0x80;
    if (used > 56) {
        Compress(block, &state);
        block.fill(0);
    }
    const uint64_t bits = static_cast<uint64_t>(password.size()) * 8;
    for (size_t i = 0; i < 8; ++i) block[63 - i] = static_cast<uint8_t>(bits >> (i * 8));
    Compress(block, &state);
    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < digest.size(); ++i) {
        digest[i] = static_cast<uint8_t>(state[i / 4] >> ((3 - i % 4) * 8));
    }
    return digest;
}

}  // namespace cbk
