#pragma once

#include <cstddef>
#include "falcon/core/frame.hpp"
#include "falcon/core/stats.hpp"

namespace falcon {

template <typename Derived>
class PacketIO {
public:
    size_t recv(Frame* out, size_t max) {
        return derived().recvImpl(out, max);
    }

    const PacketStats& stats() const {
        return derived().statsImpl();
    }

protected:
    Derived& derived() {
        return static_cast<Derived&>(*this);
    }

    const Derived& derived() const {
        return static_cast<const Derived&>(*this);
    }

    ~PacketIO() = default;

private:
    // Derived must implement:
    //   size_t recvImpl(Frame* out, size_t max)
    //   const PacketStats& statsImpl() const
};

} // namespace falcon
