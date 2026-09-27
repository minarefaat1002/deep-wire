#include "capture_engine.hpp"
#include "packet_parser.hpp"

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

// A signal can interrupt the capture loop and set this flag at any point.
// With an ordinary int, the handler's write and the loop's read are not valid
// signal communication: the compiler may reuse an earlier value, and the
// conflicting accesses can be a data race. volatile makes each loop check
// read the flag again; sig_atomic_t makes this read/write safe when the
// handler interrupts the same thread. This is a stop flag, not a general
// thread synchronization mechanism.
volatile std::sig_atomic_t stop_requested = 0;

// std::signal calls this when SIGINT (Ctrl+C) or SIGTERM arrives. extern "C"
// gives it C language linkage for the C-style signal-handler interface.
// The int parameter is the signal number; it has no name because we do not
// need to distinguish the two signals. Only set the flag here: the main loop
// notices it on its next check and performs the normal shutdown.
extern "C" void request_stop(int)
{
    stop_requested = 1;
}

// Show valid command-line forms using argv[0] as the displayed program name.
void print_usage(const char* program_name)
{
    // std::cout writes to standard output; each << appends the next piece.
    // <interface> is required, [frame-count] is optional, and \n starts a
    // new line. The final lines show concrete commands a user can run.
    std::cout
        << "Usage:\n"
        << "  " << program_name << " --list\n"
        << "  " << program_name << " <interface> [frame-count]\n\n"
        << "Examples:\n"
        << "  " << program_name << " --list\n"
        << "  " << program_name << " wlp0s20f3 10\n";
}

// Convert the frame-count argument from text to a positive 64-bit integer.
std::uint64_t parse_frame_count(const std::string_view text)
{
    // Value-initialize the output to zero before from_chars writes into it.
    std::uint64_t count{};
    // from_chars reads [begin, end): begin is the first character and end
    // points just past the last. It does not require a null-terminated string.
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    // Parse decimal digits into count. The returned position is the first
    // unparsed character; error reports invalid input or an out-of-range value.
    const auto [position, error] = std::from_chars(begin, end, count);

    // Require success, consumption of every character, and a nonzero count.
    if (error != std::errc{} || position != end || count == 0U) {
        throw std::invalid_argument(
            "frame-count must be a positive integer");
    }
    // Return the validated number of frames the caller should capture.
    return count;
}

// Query the OS through CaptureEngine and print the available interface names.
void print_interfaces()
{
    // list_interfaces() returns an owning vector of index/name pairs.
    const auto interfaces = deep_wire::CaptureEngine::list_interfaces();
    // Explain an empty result and stop this helper without printing a header.
    if (interfaces.empty()) {
        std::cout << "No network interfaces found.\n";
        return;
    }

    std::cout << "Available interfaces:\n";
    // Read each entry by reference, avoiding a copy of its name string.
    for (const auto& interface : interfaces) {
        // Show the kernel-assigned index in brackets, then the interface name.
        std::cout << "  [" << interface.index << "] "
                  << interface.name << '\n';
    }
}

void print_timestamp(const std::chrono::system_clock::time_point timestamp)
{
    using namespace std::chrono;
    const auto whole_seconds = time_point_cast<seconds>(timestamp);
    const auto nanosecond_part =
        duration_cast<nanoseconds>(timestamp - whole_seconds).count();
    const std::time_t time = system_clock::to_time_t(whole_seconds);

    std::tm utc_time{};
    if (::gmtime_r(&time, &utc_time) == nullptr) {
        throw std::runtime_error("could not format packet timestamp");
    }

    std::cout << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%S")
              << '.' << std::setfill('0') << std::setw(9)
              << nanosecond_part << "Z" << std::setfill(' ');
}

int capture_frames(const std::string_view interface_name,
    const std::uint64_t frame_count)
{
    deep_wire::CaptureEngine capture{std::string{interface_name}};
    capture.open();

    std::cout << "Capturing " << frame_count << " frame"
              << (frame_count == 1U ? "" : "s") << " on "
              << capture.interface_name()
              << ". Press Ctrl+C to stop.\n\n";

    std::uint64_t captured_frames{};
    while (captured_frames < frame_count && stop_requested == 0) {
        auto frame = capture.receive_next(
            captured_frames + 1U, std::chrono::milliseconds{500});
        if (!frame.has_value()) {
            continue;
        }

        ++captured_frames;
        const auto packet = deep_wire::PacketParser::parse(std::move(*frame));
        std::cout << "Frame " << packet.frame.number << ": timestamp=";
        print_timestamp(packet.frame.timestamp);
        std::cout << " captured=" << packet.frame.captured_length
                  << " original=" << packet.frame.original_length;
        if (packet.frame.truncated()) {
            std::cout << " [truncated]";
        }
        std::cout << " protocol=" << packet.protocol;
        if (!packet.source.empty()) {
            std::cout << " " << packet.source << " -> " << packet.destination;
        }
        if (!packet.info.empty()) {
            std::cout << " " << packet.info;
        }
        if (!packet.error.empty()) {
            std::cout << " [" << packet.error << ']';
        }
        std::cout << '\n';
    }

    std::cout << "\nCapture stopped after " << captured_frames
              << " frame" << (captured_frames == 1U ? "" : "s")
              << ".\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        std::signal(SIGINT, request_stop);
        std::signal(SIGTERM, request_stop);

        if (argc == 2 && std::string_view{argv[1]} == "--list") {
            print_interfaces();
            return 0;
        }
        if (argc == 2 && (std::string_view{argv[1]} == "--help"
                || std::string_view{argv[1]} == "-h")) {
            print_usage(argv[0]);
            return 0;
        }
        if (argc < 2 || argc > 3) {
            print_usage(argv[0]);
            return 2;
        }

        const std::uint64_t frame_count = argc == 3
            ? parse_frame_count(argv[2])
            : 10U;
        return capture_frames(argv[1], frame_count);
    } catch (const std::system_error& error) {
        std::cerr << "System error: " << error.what() << '\n';
        if (error.code() == std::errc::operation_not_permitted
            || error.code() == std::errc::permission_denied) {
            std::cerr
                << "Raw packet capture requires CAP_NET_RAW. "
                   "Run this executable with the required capability "
                   "or appropriate privileges.\n";
        }
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
