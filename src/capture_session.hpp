#pragma once

#include "packet_decoder.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace deep_wire {

// Runs capture and decoding on one background thread. The GUI periodically
// takes ownership of pending packets; the worker never accesses Qt widgets.
class CaptureSession {
public:
    // Result of take_update(): packets are removed from the handoff buffer;
    // error and finished are snapshots of the capture session's state.
    struct Update {
        // Decoded packets waiting for the GUI since the previous take_update().
        std::vector<Packet> packets;
        // Capture-level failure, such as an interface or socket error. An
        // individual malformed packet reports its own error in Packet::error.
        std::string error;
        // True when no capture is running: either start() has not been called
        // or the current capture has stopped. Packets may still be pending.
        bool finished{};
    };

    // The copy constructor below counts as a declared constructor, so C++
    // will not generate a no-argument constructor unless we request it.
    // so we define a no argment constructor ourseves.
    CaptureSession() = default;
    ~CaptureSession();
    // One session owns one worker and its shared state, so it cannot be copied.
    // This forbids creating a new session from an existing one.
    CaptureSession(const CaptureSession&) = delete;
    // This forbids assigning one existing session to another.
    CaptureSession& operator=(const CaptureSession&) = delete;

    void start(std::string interface_name, std::uint64_t packet_limit);
    void request_stop();
    [[nodiscard]] Update take_update();

private:
    void capture(std::stop_token stop, const std::string& interface_name,
        std::uint64_t packet_limit);

    // Backpressure bounds the handoff queue, including when the GUI is busy.
    static constexpr std::size_t pending_limit = 256U;
    std::mutex mutex_;
    std::condition_variable_any space_available_;
    std::vector<Packet> pending_;
    std::string error_;
    bool finished_{true};
    // Declared last so the thread is destroyed before its shared state.
    // ~CaptureSession() requests that the worker stop, then joins it (waits for
    // it to finish) before any members are destroyed.
    std::jthread worker_;
};

} // namespace deep_wire
