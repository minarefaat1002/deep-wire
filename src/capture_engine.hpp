#pragma once

#include "captured_frame.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace deep_wire {

struct NetworkInterface {
    unsigned int index{};
    std::string name;
};

class CaptureEngine {
public:
    explicit CaptureEngine(std::string interface_name);
    ~CaptureEngine();

    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;
    CaptureEngine(CaptureEngine&&) = delete;
    CaptureEngine& operator=(CaptureEngine&&) = delete;

    [[nodiscard]] static std::vector<NetworkInterface> list_interfaces();

    void open();
    void close() noexcept;

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] const std::string& interface_name() const noexcept;

    [[nodiscard]] std::optional<CapturedFrame> receive_next(
        std::uint64_t frame_number,
        std::chrono::milliseconds timeout);

private:
    static constexpr std::size_t receive_buffer_size = 256U * 1024U;

    std::string interface_name_;
    unsigned int interface_index_{};
    int socket_fd_{-1};
    std::vector<std::uint8_t> receive_buffer_;
};

} // namespace deep_wire
