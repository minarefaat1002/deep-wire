#include "capture_engine.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace deep_wire {
namespace {

// Throw a C++ exception containing the current errno value and the name of the
// system operation that failed. [[noreturn]] tells the compiler and readers
// that this helper always throws and never returns to its caller.
[[noreturn]] void throw_system_error(const char* operation)
{
    // generic_category() interprets errno using the platform's standard error
    // codes; operation is included as context in the exception message.
    throw std::system_error(errno, std::generic_category(), operation);
}

// Convert a POSIX timespec (whole seconds plus nanoseconds) into C++'s
// system_clock time-point representation.
std::chrono::system_clock::time_point to_time_point(const timespec& timestamp)
{
    // Make chrono type names available locally without qualifying each one.
    using namespace std::chrono;

    // Construct the time point by adding both components of the POSIX timestamp.
    return system_clock::time_point{seconds{timestamp.tv_sec}
        + nanoseconds{timestamp.tv_nsec}};
}

} // namespace: keep these helper functions private to this source file

// Construct an engine for one named network interface. Taking the string by
// value allows it to be moved efficiently into the object's member.
CaptureEngine::CaptureEngine(std::string interface_name)
    // Move the supplied name instead of copying it, then allocate the fixed-size
    // storage used to receive captured frame bytes.
    : interface_name_(std::move(interface_name)),
      receive_buffer_(receive_buffer_size)
{
    // Reject an unusable engine immediately instead of failing later in open().
    if (interface_name_.empty()) {
        throw std::invalid_argument("interface name must not be empty");
    }
}

// Release the raw packet socket automatically when the engine's lifetime ends.
CaptureEngine::~CaptureEngine()
{
    // close() is safe even when the engine was never opened or was already closed.
    close();
}

std::vector<NetworkInterface> CaptureEngine::list_interfaces()
{
    // Ask the OS for a newly allocated, sentinel-terminated array of interfaces.
    // raw_interfaces points to the first array entry but does not clean it up itself.
    struct if_nameindex* raw_interfaces = ::if_nameindex();

    // A null pointer means that the OS could not produce the interface list.
    if (raw_interfaces == nullptr) {
        // Convert the errno value set by if_nameindex() into a C++ exception.
        throw_system_error("if_nameindex");
    }

    // Define the cleanup operation required by the C API. The returned array must
    // be released with if_freenameindex(), not with delete or delete[].
    const auto free_interfaces = [](struct if_nameindex* interfaces) {
        ::if_freenameindex(interfaces);
    };

    // Transfer cleanup responsibility to a unique_ptr. Its second template
    // argument is the lambda's compiler-generated type. When this local variable
    // is destroyed, it calls free_interfaces(raw_interfaces), including when an
    // exception interrupts the function.
    const std::unique_ptr<struct if_nameindex, decltype(free_interfaces)> interfaces(
        raw_interfaces, free_interfaces);

    // Build an owning C++ result whose strings remain valid after the C array is freed.
    std::vector<NetworkInterface> result;

    // get() exposes the owned pointer without transferring ownership. current is
    // read-only and advances through the contiguous if_nameindex array.
    for (const struct if_nameindex* current = interfaces.get();
         // The C API marks the end with {0, nullptr}; process only valid entries.
         current->if_index != 0U && current->if_name != nullptr;
         // Pointer increment moves to the next if_nameindex structure in the array.
         ++current) {
        // Copy the numeric index and C string into an independently owned object.
        result.push_back(NetworkInterface{current->if_index, current->if_name});
    }

    // Return the independent C++ collection; interfaces then frees the C array.
    return result;
}

// Create a packet socket and attach it to the interface named at construction.
void CaptureEngine::open()
{
    // Reopening would replace an already-owned socket without closing it.
    if (is_open()) {
        throw std::logic_error("capture engine is already open");
    }

    // Resolve the interface name to its current kernel index. Keep the index
    // local until the socket is fully configured, so failure leaves us closed.
    const unsigned int interface_index = ::if_nametoindex(interface_name_.c_str());
    // A zero index means the lookup failed; errno explains why.
    if (interface_index == 0U) {
        throw_system_error("if_nametoindex");
    }

    // AF_PACKET accesses link-layer frames; SOCK_RAW includes their link header.
    // SOCK_CLOEXEC closes the descriptor on exec, and ETH_P_ALL selects every
    // Ethernet protocol type. htons converts that type to network byte order.
    const int descriptor = ::socket(
        AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    // socket() returns -1 on failure, before there is a descriptor to close.
    if (descriptor == -1) {
        throw_system_error("socket(AF_PACKET)");
    }

    // Close this local descriptor explicitly if a later setup step fails.
    // The reference capture lets the lambda use the descriptor above.
    const auto close_on_error = [&descriptor]() {
        ::close(descriptor);
    };

    // A nonzero value enables receive timestamps. Later recvmsg() calls
    // receive a timespec in SCM_TIMESTAMPNS control data beside each frame.
    const int timestamp_enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_TIMESTAMPNS,
            &timestamp_enabled, sizeof(timestamp_enabled)) == -1) {
        // Preserve the setsockopt() error before close() can change errno.
        const int saved_errno = errno;
        close_on_error();
        errno = saved_errno;
        throw_system_error("setsockopt(SO_TIMESTAMPNS)");
    }

    // Zero-initialize a packet-socket address, then specify the family,
    // protocol selection, and interface to which this socket will be bound.
    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(interface_index);

    // bind() accepts a generic sockaddr pointer; the address length tells
    // Linux that this is the larger packet-specific sockaddr_ll structure.
    if (::bind(descriptor, reinterpret_cast<const sockaddr*>(&address),
            sizeof(address)) == -1) {
        // Report the bind() error after releasing the new socket.
        const int saved_errno = errno;
        close_on_error();
        errno = saved_errno;
        throw_system_error("bind(AF_PACKET)");
    }

    // Setup succeeded: store the index and descriptor in this engine.
    interface_index_ = interface_index;
    socket_fd_ = descriptor;
}

// Release the packet socket and reset the engine to its closed state.
// noexcept promises that this cleanup function will not throw an exception.
void CaptureEngine::close() noexcept
{
    // -1 means there is no owned socket, so repeated calls are harmless.
    if (socket_fd_ != -1) {
        // Ask Linux to close the descriptor; this cleanup path ignores errors.
        ::close(socket_fd_);
        // Mark the engine closed so is_open() returns false.
        socket_fd_ = -1;
    }
    // Forget the index even if no socket was open.
    interface_index_ = 0U;
}

// const promises not to change the engine; noexcept promises not to throw.
bool CaptureEngine::is_open() const noexcept
{
    // Any value other than the -1 sentinel is an owned socket descriptor.
    return socket_fd_ != -1;
}

// Return the stored name by const reference, avoiding a string copy.
const std::string& CaptureEngine::interface_name() const noexcept
{
    // The reference remains valid while this CaptureEngine object exists.
    return interface_name_;
}

// Wait for one packet up to the timeout. Return an empty optional when no
// frame arrives, or throw if the socket cannot be used.
std::optional<CapturedFrame> CaptureEngine::receive_next(
    const std::uint64_t frame_number,
    const std::chrono::milliseconds timeout)
{
    if (!is_open()) {
        throw std::logic_error("capture engine is not open");
    }
    // poll() accepts an int number of milliseconds.
    if (timeout.count() < 0 || timeout.count() > INT_MAX) {
        throw std::invalid_argument("capture timeout is out of range");
    }

    // pollfd names the descriptor to watch and holds the returned event bits.
    pollfd event{};
    event.fd = socket_fd_;
    // Ask poll to wait for a packet to read. POLLOUT asks about writing,
    // and POLLPRI asks about exceptional data. POLLERR, POLLHUP, and
    // POLLNVAL are reported in revents even when not requested here.
    event.events = POLLIN;

    // Watch this one descriptor; poll writes the result into event.revents.
    const int poll_result = ::poll(
        &event, 1, static_cast<int>(timeout.count()));
    // Zero means the timeout expired before a packet became ready. No frame
    // was captured, so let the caller retry or check whether it should stop.
    if (poll_result == 0) {
        return std::nullopt;
    }
    if (poll_result == -1) {
        if (errno == EINTR) {
            // A handled signal interrupted the wait. Let the caller return
            // to its loop so it can check whether shutdown was requested.
            return std::nullopt;
        }
        throw_system_error("poll(AF_PACKET)");
    }
    // revents is a bitmask. Error and hangup bits can be reported even
    // though only POLLIN was requested in event.events.
    if ((event.revents & POLLNVAL) != 0) {
        throw std::runtime_error("packet socket became invalid");
    }
    if ((event.revents & (POLLERR | POLLHUP)) != 0) {
        throw std::runtime_error("packet socket reported an error");
    }
    // Do not call recvmsg unless poll reported readable packet data.
    if ((event.revents & POLLIN) == 0) {
        return std::nullopt;
    }

    // iovec describes the memory where recvmsg will place packet bytes;
    // it points to receive_buffer_ but does not own that storage.
    iovec data_buffer{};
    data_buffer.iov_base = receive_buffer_.data();
    data_buffer.iov_len = receive_buffer_.size();

    // SO_TIMESTAMPNS supplies a timespec in a control message beside the
    // packet. Reserve room for its header, payload, and padding; align the
    // byte array so its cmsghdr can be accessed safely.
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(timespec))> control{};
    // msghdr gives recvmsg both destinations: packet bytes and control data.
    msghdr message{};
    message.msg_iov = &data_buffer;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    // The kernel copies at most iov_len bytes into receive_buffer_. For an
    // AF_PACKET socket, MSG_TRUNC returns the full packet size even if some
    // bytes did not fit and were discarded.
    const ssize_t received = ::recvmsg(socket_fd_, &message, MSG_TRUNC);
    if (received == -1) {
        if (errno == EINTR) {
            // A signal interrupted recvmsg before a frame was received.
            return std::nullopt;
        }
        throw_system_error("recvmsg(AF_PACKET)");
    }

    // Control messages are separate from packet bytes. Walk their headers
    // to find the receive timestamp enabled by SO_TIMESTAMPNS in open().
    std::optional<timespec> kernel_timestamp;
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        // Match the socket-level timestamp and verify its payload length.
        if (header->cmsg_level == SOL_SOCKET
            && header->cmsg_type == SCM_TIMESTAMPNS
            && header->cmsg_len >= CMSG_LEN(sizeof(timespec))) {
            timespec timestamp{};
            // CMSG_DATA need not be aligned for timespec, so copy its bytes.
            std::memcpy(&timestamp, CMSG_DATA(header), sizeof(timestamp));
            kernel_timestamp = timestamp;
            break;
        }
    }

    // The timestamp was requested when the socket opened; do not invent one.
    if (!kernel_timestamp.has_value()) {
        throw std::runtime_error(
            "kernel timestamp missing from received packet");
    }

    // MSG_TRUNC can report more bytes than the vector could hold. Keep the
    // original size, and limit captured size to bytes actually copied.
    const auto original_length = static_cast<std::size_t>(received);
    const auto captured_length =
        std::min(original_length, receive_buffer_.size());

    CapturedFrame frame;
    frame.number = frame_number;
    frame.timestamp = to_time_point(*kernel_timestamp);
    // Give the frame its own copy before the next receive reuses the buffer.
    frame.data.assign(receive_buffer_.begin(),
        receive_buffer_.begin() + static_cast<std::ptrdiff_t>(captured_length));
    frame.captured_length = captured_length;
    frame.original_length = original_length;
    return frame;
}

} // namespace deep_wire
