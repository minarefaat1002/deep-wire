#include "capture_session.hpp"
#include "capture_engine.hpp"

#include <chrono>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace deep_wire {

// Stop the background capture before the session's mutex, queue, and other
// shared state are destroyed. The worker uses all of those members.
CaptureSession::~CaptureSession()
{
    // Request cooperative cancellation; this does not wait for the worker.
    request_stop();
    // joinable() checks whether worker_ still owns a thread, not whether it is
    // still running. A finished worker remains joinable until joined. join()
    // waits if needed, then makes worker_ non-joinable; the check avoids
    // calling it when no thread is owned. std::jthread would also request
    // stop and join automatically during its own destruction.
    if (worker_.joinable()) worker_.join();
}

// Replace any previous capture with a new one on the requested interface.
// A zero limit is invalid; other setup failures are reported by the worker
// through take_update(), except failure to create the worker thread itself.
void CaptureSession::start(std::string interface_name,
    const std::uint64_t packet_limit)
{
    // Check this before stopping an existing capture, so a bad limit does not
    // interrupt it.
    if (packet_limit == 0U) {
        throw std::invalid_argument("packet limit must be positive");
    }
    // Finish any previous worker before resetting its results or starting anew.
    // Joining also ensures the old worker can no longer touch shared state.
    request_stop();
    if (worker_.joinable()) worker_.join();
    // The current GUI calls start() and take_update() on the same thread, and
    // the old worker has joined before this reset. This lock is not needed for
    // that call pattern; it keeps a future concurrent take_update() from seeing
    // a partial reset. The scope releases it before thread creation, allowing
    // the catch block to lock it again if thread creation fails.
    {
        std::lock_guard lock{mutex_};
        // Discard packets and status from the previous run. The next update
        // must describe only this new capture.
        pending_.clear();
        error_.clear();
        statistics_.reset();
        statistics_failed_ = false;
        finished_ = false;
    }
    try {
        // jthread owns the new worker. Move the interface name into its lambda
        // so the string remains alive for the worker's entire capture call.
        // The stop token belongs to this jthread and is passed to capture().
        worker_ = std::jthread{[this, name = std::move(interface_name), packet_limit]
            (const std::stop_token stop) { capture(stop, name, packet_limit); }};
    } catch (...) {
        // If constructing the thread throws, there is no worker to set the
        // completion flag. Restore a finished state, then preserve the error.
        std::lock_guard lock{mutex_};
        finished_ = true;
        throw;
    }
}

// Ask the worker to stop without waiting for it to exit. notify_all() also
// wakes a worker blocked because the packet handoff queue is full.
void CaptureSession::request_stop()
{
    worker_.request_stop();
    space_available_.notify_all();
}

// Transfer queued packets to the caller and read the latest status. The GUI
// can then process its own packet vector without holding the worker's mutex.
CaptureSession::Update CaptureSession::take_update()
{
    Update update;
    {
        std::lock_guard lock{mutex_};
        // swap() empties pending_ by exchanging it with the new empty vector;
        // the returned vector now owns all packets queued so far.
        update.packets.swap(pending_);
        // Error and completion remain available on later polls until start()
        // resets them for another run.
        update.error = error_;
        update.statistics = statistics_;
        update.statistics_unavailable = statistics_failed_;
        update.finished = finished_;
    }
    // The worker may have paused at the 256-packet limit. Wake it now that
    // the queue has space; release the lock before it tries to acquire it.
    space_available_.notify_all();
    return update;
}

void CaptureSession::update_statistics(CaptureEngine& engine)
{
    // Only the worker accesses this flag; start() resets it after joining.
    if (statistics_failed_) return;
    const auto delta = engine.take_statistics();
    std::lock_guard lock{mutex_};
    if (!delta) {
        // Continue capture, but keep incomplete measurements unavailable.
        statistics_.reset();
        statistics_failed_ = true;
        return;
    }
    if (!statistics_) statistics_ = CaptureStatistics{};
    statistics_->packets += delta->packets;
    statistics_->dropped += delta->dropped;
}

// Worker-thread entry point: receive, decode, and hand packets to the GUI
// until the packet limit, cancellation, or a capture-level error.
void CaptureSession::capture(const std::stop_token stop,
    const std::string& interface_name, const std::uint64_t packet_limit)
{
    // Keep the socket alive through error handling for the final stats read.
    std::optional<CaptureEngine> engine;
    try {
        // CaptureEngine owns the raw socket and closes it when this scope ends.
        // Construction and open() can throw, just like receive_next() can.
        engine.emplace(interface_name);
        engine->open();
        update_statistics(*engine);
        auto next_statistics = std::chrono::steady_clock::now() + std::chrono::seconds{1};
        // Number of frames successfully delivered to the handoff queue. This
        // also supplies the next frame's one-based number to receive_next().
        std::uint64_t captured{};
        while (captured < packet_limit && !stop.stop_requested()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= next_statistics) {
                update_statistics(*engine);
                next_statistics = now + std::chrono::seconds{1};
            }
            // Wait for handoff space before receiving another frame. The
            // stop-token wait also wakes during window closure or Stop. The
            // condition-variable wait releases mutex_ while it is blocked.
            {
                std::unique_lock lock{mutex_};
                if (!space_available_.wait(lock, stop,
                        [this] { return pending_.size() < pending_limit; })) {
                    // The wait ended without room, typically because a stop
                    // was requested while the queue was full.
                    break;
                }
            }
            // A 100 ms timeout lets the loop recheck cancellation even when
            // no traffic arrives. An empty optional means no frame this time.
            auto frame = engine->receive_next(captured + 1U, std::chrono::milliseconds{100});
            if (!frame) continue;
            // decode() takes ownership of the captured frame. Hold the mutex
            // only while adding the resulting packet to the shared queue.
            auto packet = PacketDecoder::decode(std::move(*frame));
            std::lock_guard lock{mutex_};
            pending_.push_back(std::move(packet));
            ++captured;
        }
    } catch (const std::exception& error) {
        // CaptureEngine and the decoder report ordinary failures as standard
        // exceptions. Save their message for the GUI instead of letting an
        // exception escape the worker thread.
        std::lock_guard lock{mutex_};
        error_ = error.what();
        // dynamic_cast tests the exception's actual runtime type. It returns
        // nullptr for other std::exception subclasses; only system_error has
        // a code() to compare with permission-related error conditions.
        if (const auto* system_error = dynamic_cast<const std::system_error*>(&error);
            system_error && (system_error->code() == std::errc::operation_not_permitted
                || system_error->code() == std::errc::permission_denied)) {
            error_ += ". Packet capture requires CAP_NET_RAW.";
        }
    }
    if (engine && engine->is_open()) {
        update_statistics(*engine);
        engine->close();
    }
    // Either the limit was reached, stop was requested, or an error occurred.
    // The GUI can still drain packets already queued after finished_ is true.
    std::lock_guard lock{mutex_};
    finished_ = true;
}

} // namespace deep_wire
