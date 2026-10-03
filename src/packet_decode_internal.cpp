#include "packet_decode_internal.hpp"

// Common result-recording and address-formatting helpers used by the protocol
// decoders. ByteView borrows captured bytes; these helpers return owned strings
// or store owned layer metadata in the Packet referenced by DecodeContext.
// Address helpers do not validate bounds: callers must check the required byte
// range before calling them, and keep the underlying frame storage valid.

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

// POSIX IPv6 text conversion and its maximum output-buffer size.
#include <arpa/inet.h>

namespace deep_wire::decoding {

// Record a successfully decoded header and make its name the summary protocol.
// bytes starts at this layer's header; its absolute offset locates that header
// in the original captured frame. header_length describes only the header,
// excluding payload, and must already have been validated against bytes.
// fields contains ordered display name/value pairs for the packet details.
void DecodeContext::add_layer(std::string name, ByteView bytes,
    std::size_t header_length, Fields fields)
{
    // DecodedLayer stores metadata, not the ByteView or a copy of frame bytes.
    // Copy name into the layer before moving it into the packet summary;
    // move fields because this function no longer needs their contents.
    packet.layers.push_back(
        {name, bytes.absolute, header_length, std::move(fields)});
    // As decoding progresses inward, the most recently added layer becomes
    // the displayed protocol (for example, Ethernet -> IPv4 -> TCP).
    packet.protocol = std::move(name);
}

// Replace the packet's diagnostic while retaining already decoded layers and
// summary fields. This records an error; it does not itself stop decoding or
// explicitly throw an exception. The caller decides whether to return.
void DecodeContext::fail(std::string message)
{
    packet.error = std::move(message);
}

// Render a numeric 16-bit value as lowercase hexadecimal with a literal "0x"
// prefix and exactly four digits, such as 0x0800 for the IPv4 EtherType.
// The input is already a numeric value; no byte-order conversion occurs here.
std::string hex16(const std::uint16_t value)
{
    std::ostringstream out;
    // setw applies to the next insertion only; zero fill supplies leading
    // digits. A uint16_t cannot need more than four hexadecimal digits.
    out << "0x" << std::hex << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

// Format the six octets beginning at view-relative offset at as a lowercase,
// colon-separated MAC address, for example "00:1a:2b:03:04:ff".
// Requires bytes.has(at, 6); this helper performs no length checks.
std::string mac_address(const ByteView bytes, const std::size_t at)
{
    std::ostringstream out;
    // Hexadecimal mode and the fill character persist across insertions.
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < 6U; ++i) {
        // Insert separators only between octets, with no leading/trailing ':'.
        if (i != 0U) out << ':';
        // Reapply the two-digit width for each octet. Promote uint8_t to an
        // integer so the stream prints its value instead of a character.
        out << std::setw(2) << static_cast<unsigned int>(bytes.u8(at + i));
    }
    return out.str();
}

// Format four octets at view-relative offset at in dotted-decimal notation,
// for example "192.0.2.1". Requires bytes.has(at, 4).
// Reading octets in wire order avoids host byte-order and alignment concerns.
std::string ipv4_address(const ByteView bytes, const std::size_t at)
{
    // Each byte becomes its decimal value (0..255), without zero padding.
    return std::to_string(bytes.u8(at)) + '.'
        + std::to_string(bytes.u8(at + 1U)) + '.'
        + std::to_string(bytes.u8(at + 2U)) + '.'
        + std::to_string(bytes.u8(at + 3U));
}

// Format sixteen octets at view-relative offset at using the platform's IPv6
// presentation format, including zero compression where applicable.
// Requires bytes.has(at, 16); inet_ntop receives a pointer, not a bounded view,
// so a failed conversion is not a substitute for validating the input range.
std::string ipv6_address(const ByteView bytes, const std::size_t at)
{
    // INET6_ADDRSTRLEN allows room for the IPv6 text and its terminating NUL.
    // The array owns the output buffer for the duration of the conversion.
    std::array<char, INET6_ADDRSTRLEN> text{};
    // AF_INET6 tells inet_ntop to interpret the source as a 16-byte address in
    // network byte order. at is relative to this view, not the original frame.
    if (::inet_ntop(AF_INET6, bytes.data.data() + at,
            text.data(), static_cast<socklen_t>(text.size())) == nullptr) {
        // Expose conversion failure as display text instead of reading output
        // from an unsuccessful call. This does not set Packet::error.
        return "<invalid IPv6 address>";
    }
    // Copy the NUL-terminated output into an owned string before text expires.
    return text.data();
}

} // namespace deep_wire::decoding
