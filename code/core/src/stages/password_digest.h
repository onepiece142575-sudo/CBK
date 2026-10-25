// Copyright 2026 CBK Project.
#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace cbk {

/// SHA-256 for folding a complete long password into the legacy CBC key block.
/// Implemented locally; no operating-system cryptography or third-party library.
std::array<uint8_t, 32> PasswordDigest(const std::string& password);

}  // namespace cbk
