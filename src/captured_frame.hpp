#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace deep_wire {

// One capture record received from the Linux AF_PACKET socket.
// It owns the captured bytes but does not decode their protocol headers.
struct CapturedFrame {
    // Sequential identifier assigned by Deep Wire, not a value from the frame.
    std::uint64_t number{};

    // Arrival time supplied by the kernel through SO_TIMESTAMPNS.
    std::chrono::system_clock::time_point timestamp{};

    // Owned copy of the bytes that were actually available to capture.
    std::vector<std::uint8_t> data;

    // Number of valid bytes stored in data and safe for a parser to read.
    std::size_t captured_length{};

    // Full frame length reported by recvmsg(MSG_TRUNC). This can be larger
    // than captured_length if the receive buffer was too small.
    std::size_t original_length{};

    // Reports whether any bytes from the original frame were not captured.
    [[nodiscard]] bool truncated() const noexcept
    {
        return captured_length < original_length;
    }
};

} // namespace deep_wire
