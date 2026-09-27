#include "packet_parser.hpp"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace deep_wire {
namespace {

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t at)
{
    return static_cast<std::uint16_t>(
        (static_cast<unsigned int>(bytes[at]) << 8U) | bytes[at + 1U]);
}

std::string mac_address(const std::vector<std::uint8_t>& bytes, std::size_t at)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < 6U; ++i) {
        if (i != 0U) out << ':';
        out << std::setw(2) << static_cast<unsigned int>(bytes[at + i]);
    }
    return out.str();
}

std::string ipv4_address(const std::vector<std::uint8_t>& bytes, std::size_t at)
{
    return std::to_string(bytes[at]) + '.' + std::to_string(bytes[at + 1U])
        + '.' + std::to_string(bytes[at + 2U]) + '.'
        + std::to_string(bytes[at + 3U]);
}

} // namespace

Packet PacketParser::parse(CapturedFrame frame)
{
    Packet packet;
    packet.frame = std::move(frame);
    const auto& bytes = packet.frame.data;
    const auto has = [&bytes](std::size_t at, std::size_t count) {
        return at <= bytes.size() && count <= bytes.size() - at;
    };

    // On an Ethernet interface, frame.data is one contiguous frame:
    // bytes 0-5: destination MAC; 6-11: source MAC; 12-13: EtherType.
    // Byte 14 starts the next header: IPv4 directly, or a 4-byte VLAN tag
    // whose inner type tells us what follows. IP, TCP/UDP, and payload bytes
    // stay in this same vector; their offsets are measured from its start.
    if (!has(0U, 14U)) {
        packet.error = "short Ethernet header";
        return packet;
    }
    packet.destination = mac_address(bytes, 0U);
    packet.source = mac_address(bytes, 6U);
    packet.protocol = "Ethernet";
    std::uint16_t type = read_u16(bytes, 12U);
    packet.layers.push_back({"Ethernet", 0U, 14U,
        {{"Destination", packet.destination}, {"Source", packet.source},
            {"Type", std::to_string(type)}}});

    std::size_t offset = 14U;
    while (type == 0x8100U || type == 0x88a8U) {
        if (!has(offset, 4U)) {
            packet.error = "short VLAN header";
            return packet;
        }
        const auto tag = read_u16(bytes, offset);
        type = read_u16(bytes, offset + 2U);
        packet.layers.push_back({"VLAN", offset, 4U,
            {{"ID", std::to_string(tag & 0x0fffU)},
                {"Inner type", std::to_string(type)}}});
        packet.protocol = "VLAN";
        offset += 4U;
    }

    if (type != 0x0800U) {
        packet.info = "EtherType " + std::to_string(type);
        return packet;
    }
    if (!has(offset, 20U)) {
        packet.error = "short IPv4 header";
        return packet;
    }
    const auto version = static_cast<unsigned int>(bytes[offset] >> 4U);
    const auto ip_header_length =
        static_cast<std::size_t>(bytes[offset] & 0x0fU) * 4U;
    if (version != 4U || ip_header_length < 20U || !has(offset, ip_header_length)) {
        packet.error = "invalid or short IPv4 header";
        return packet;
    }
    const auto ip_length = static_cast<std::size_t>(read_u16(bytes, offset + 2U));
    if (ip_length < ip_header_length) {
        packet.error = "IPv4 total length is smaller than its header";
        return packet;
    }
    packet.source = ipv4_address(bytes, offset + 12U);
    packet.destination = ipv4_address(bytes, offset + 16U);
    packet.protocol = "IPv4";
    packet.layers.push_back({"IPv4", offset, ip_header_length,
        {{"Source", packet.source}, {"Destination", packet.destination},
            {"Total length", std::to_string(ip_length)},
            {"Protocol number", std::to_string(bytes[offset + 9U])}}});
    if (!has(offset, ip_length)) {
        packet.error = "truncated IPv4 packet";
        return packet;
    }
    const auto fragment = read_u16(bytes, offset + 6U);
    if ((fragment & 0x3fffU) != 0U) {
        packet.info = "IPv4 fragment; transport decoding deferred";
        return packet;
    }

    const auto transport = offset + ip_header_length;
    const auto transport_length = ip_length - ip_header_length;
    const auto ip_protocol = bytes[offset + 9U];
    if (ip_protocol == 6U) {
        if (transport_length < 20U) {
            packet.error = "short TCP header";
            return packet;
        }
        const auto header_length =
            static_cast<std::size_t>(bytes[transport + 12U] >> 4U) * 4U;
        if (header_length < 20U || header_length > transport_length) {
            packet.error = "invalid TCP header length";
            return packet;
        }
        const auto source_port = read_u16(bytes, transport);
        const auto destination_port = read_u16(bytes, transport + 2U);
        packet.protocol = "TCP";
        packet.info = std::to_string(source_port) + " -> "
            + std::to_string(destination_port);
        packet.layers.push_back({"TCP", transport, header_length,
            {{"Source port", std::to_string(source_port)},
                {"Destination port", std::to_string(destination_port)},
                {"Payload length", std::to_string(transport_length - header_length)}}});
    } else if (ip_protocol == 17U) {
        if (transport_length < 8U) {
            packet.error = "short UDP header";
            return packet;
        }
        const auto udp_length = static_cast<std::size_t>(read_u16(bytes, transport + 4U));
        if (udp_length < 8U || udp_length > transport_length) {
            packet.error = "invalid UDP length";
            return packet;
        }
        const auto source_port = read_u16(bytes, transport);
        const auto destination_port = read_u16(bytes, transport + 2U);
        packet.protocol = "UDP";
        packet.info = std::to_string(source_port) + " -> "
            + std::to_string(destination_port);
        packet.layers.push_back({"UDP", transport, 8U,
            {{"Source port", std::to_string(source_port)},
                {"Destination port", std::to_string(destination_port)},
                {"Payload length", std::to_string(udp_length - 8U)}}});
    } else {
        packet.info = "IP protocol " + std::to_string(ip_protocol);
    }
    return packet;
}

} // namespace deep_wire
