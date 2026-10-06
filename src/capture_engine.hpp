#pragma once

#include "captured_frame.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace deep_wire {

// A network interface returned by the operating system. The index and name
// are copied, so they remain valid after list_interfaces() returns.
struct NetworkInterface {
    // Kernel-assigned interface index.
    unsigned int index{};
    // Interface name used to construct a CaptureEngine (for example, "eth0").
    std::string name;
};

struct CaptureStatistics {
    // Total socket deliveries counted by Linux, including dropped packets.
    std::uint64_t packets{};
    std::uint64_t dropped{};
};

// Captures link-layer frames from one Linux network interface using an
// AF_PACKET raw socket. Call open() before receive_next(); close() or
// destruction releases the socket. The engine cannot be copied or moved.
class CaptureEngine {
public:
    // Store the interface name and allocate the receive buffer. Throws
    // std::invalid_argument if interface_name is empty; does not open a socket.
    explicit CaptureEngine(std::string interface_name);

    // Release the socket if it is still open.
    ~CaptureEngine();

    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;
    CaptureEngine(CaptureEngine&&) = delete;
    CaptureEngine& operator=(CaptureEngine&&) = delete;

    // Return the interfaces currently reported by the OS. Throws
    // std::system_error if interface enumeration fails.
    [[nodiscard]] static std::vector<NetworkInterface> list_interfaces();

    // Open and bind a raw packet socket to the named interface. Supports
    // Ethernet-style and loopback link headers. Throws std::logic_error if
    // already open, std::system_error on OS failure (including insufficient
    // socket privileges), or std::runtime_error for an unsupported link type.
    // A failed attempt leaves the engine closed.
    void open();

    // Release the socket and reset the open state. Safe to call repeatedly.
    void close() noexcept;

    // Report whether this engine currently owns an open socket.
    [[nodiscard]] bool is_open() const noexcept;

    // Return the interface name supplied at construction. The reference is
    // valid for the lifetime of this engine.
    [[nodiscard]] const std::string& interface_name() const noexcept;

    // Read and reset the kernel's socket counters. Returns nullopt if closed
    // or unavailable. Call from the capture worker and accumulate each result.
    [[nodiscard]] std::optional<CaptureStatistics> take_statistics() noexcept;

    // Wait up to timeout for one frame. timeout must be between zero and
    // INT_MAX milliseconds; zero polls without waiting. Return std::nullopt
    // on timeout or signal interruption. Otherwise return an owned copy of
    // the captured bytes, the caller-supplied frame number, the kernel arrival
    // timestamp, and both captured and original lengths. A frame may be
    // truncated if its original length exceeds the receive buffer size.
    // Throws std::logic_error if closed, std::invalid_argument for an invalid
    // timeout, std::system_error on OS failure, or std::runtime_error for a
    // socket error or missing kernel timestamp.
    [[nodiscard]] std::optional<CapturedFrame> receive_next(
        std::uint64_t frame_number,
        std::chrono::milliseconds timeout);

private:
    // Maximum number of frame bytes retained by a single receive operation.
    static constexpr std::size_t receive_buffer_size = 256U * 1024U;

    // Name retained across open/close cycles.
    std::string interface_name_;
    // Resolved when opened; zero while closed.
    unsigned int interface_index_{};
    // Owned packet socket; -1 while closed.
    int socket_fd_{-1};
    // Reused for each receive; returned frames get their own byte copy.
    std::vector<std::uint8_t> receive_buffer_;
};

} // namespace deep_wire
