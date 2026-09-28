#include "packet_decode_internal.hpp"

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

#include <arpa/inet.h>

namespace deep_wire::decoding {

void DecodeContext::add_layer(std::string name, ByteView bytes,
    std::size_t header_length, Fields fields)
{
    packet.layers.push_back(
        {name, bytes.absolute, header_length, std::move(fields)});
    packet.protocol = std::move(name);
}

void DecodeContext::fail(std::string message)
{
    packet.error = std::move(message);
}

std::string hex16(const std::uint16_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

std::string mac_address(const ByteView bytes, const std::size_t at)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < 6U; ++i) {
        if (i != 0U) out << ':';
        out << std::setw(2) << static_cast<unsigned int>(bytes.u8(at + i));
    }
    return out.str();
}

std::string ipv4_address(const ByteView bytes, const std::size_t at)
{
    return std::to_string(bytes.u8(at)) + '.'
        + std::to_string(bytes.u8(at + 1U)) + '.'
        + std::to_string(bytes.u8(at + 2U)) + '.'
        + std::to_string(bytes.u8(at + 3U));
}

std::string ipv6_address(const ByteView bytes, const std::size_t at)
{
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (::inet_ntop(AF_INET6, bytes.data.data() + at,
            text.data(), static_cast<socklen_t>(text.size())) == nullptr) {
        return "<invalid IPv6 address>";
    }
    return text.data();
}

} // namespace deep_wire::decoding
