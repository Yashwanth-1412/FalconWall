#pragma once

#include <cstdint>
#include <cstddef>

namespace falcon {

struct Frame {
    uint8_t* data_ = nullptr;
    std::size_t len_ = 0;

    Frame() = default;
    Frame(uint8_t* data, size_t len) :
        data_(data),
        len_(len)
    {}
};

} // namespace falcon
