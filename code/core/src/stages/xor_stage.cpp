// Copyright 2026 CBK Project.
#include "src/stages/xor_stage.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "cbk/sink.h"
#include "cbk/text.h"

namespace cbk {

XorStage::XorStage() = default;

std::string XorStage::Name() const {
    return "xor";
}

void XorStage::SetPassword(const std::string& password) {
    key_.clear();
    pos_ = 0;
    if (password.empty()) {
        // Empty password means no encryption, so keep a zero byte as the keystream.
        key_.push_back(0);
        return;
    }
    key_.assign(password.begin(), password.end());
    // Add one length byte to avoid a fully repeated one-byte keystream.
    key_.push_back(static_cast<uint8_t>(key_.size() & 0xFF));
}

void XorStage::Process(const uint8_t* data, size_t len, ISink& out) {
    if (len == 0) return;
    if (key_.empty()) throw std::runtime_error("encryption password is required");
    std::vector<uint8_t> buf;
    buf.resize(len);
    const size_t k = key_.empty() ? 1 : key_.size();
    for (size_t i = 0; i < len; ++i) {
        uint8_t kbyte = key_[pos_];
        buf[i] = static_cast<uint8_t>(data[i] ^ kbyte);
        if (++pos_ == k) pos_ = 0;
    }
    out.Write(buf.data(), buf.size());
}

void XorStage::Finish(ISink& /*out*/) {
    // XOR has no tail state; nothing to flush.
}

}  // namespace cbk
