#include "packet_decode_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace deep_wire::decoding {
namespace {

std::string tcp_flags(const ByteView bytes)
{
    std::string flags;
    const auto append = [&flags](const char* name) {
        if (!flags.empty()) flags += ", ";
        flags += name;
    };
    const auto bits = bytes.u8(13U);
    if ((bytes.u8(12U) & 1U) != 0U) append("NS");
    if ((bits & 0x80U) != 0U) append("CWR");
    if ((bits & 0x40U) != 0U) append("ECE");
    if ((bits & 0x20U) != 0U) append("URG");
    if ((bits & 0x10U) != 0U) append("ACK");
    if ((bits & 0x08U) != 0U) append("PSH");
    if ((bits & 0x04U) != 0U) append("RST");
    if ((bits & 0x02U) != 0U) append("SYN");
    if ((bits & 0x01U) != 0U) append("FIN");
    return flags.empty() ? "none" : flags;
}

void decode_tcp(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 20U)) {
        context.fail("short TCP header");
        return;
    }
    const auto header_length =
        static_cast<std::size_t>(bytes.u8(12U) >> 4U) * 4U;
    if (header_length < 20U || !bytes.has(0U, header_length)) {
        context.fail("invalid TCP header length");
        return;
    }

    const auto source_port = bytes.u16(0U);
    const auto destination_port = bytes.u16(2U);
    const auto flags = tcp_flags(bytes);
    const auto payload_length = bytes.data.size() - header_length;
    context.packet.info = std::to_string(source_port) + " -> "
        + std::to_string(destination_port);
    if (flags != "none") context.packet.info += " [" + flags + "]";
    context.packet.info += " Len=" + std::to_string(payload_length);
    context.add_layer("TCP", bytes, header_length,
        {{"Source port", std::to_string(source_port)},
            {"Destination port", std::to_string(destination_port)},
            {"Sequence", std::to_string(bytes.u32(4U))},
            {"Acknowledgment", std::to_string(bytes.u32(8U))},
            {"Header length", std::to_string(header_length)},
            {"Flags", flags},
            {"Window", std::to_string(bytes.u16(14U))},
            {"Checksum", hex16(bytes.u16(16U))},
            {"Payload length", std::to_string(payload_length)}});
}

void decode_udp(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 8U)) {
        context.fail("short UDP header");
        return;
    }
    const auto length = static_cast<std::size_t>(bytes.u16(4U));
    if (length < 8U || length > bytes.data.size()) {
        context.fail("invalid UDP length");
        return;
    }
    const auto source_port = bytes.u16(0U);
    const auto destination_port = bytes.u16(2U);
    context.packet.info = std::to_string(source_port) + " -> "
        + std::to_string(destination_port) + " Len="
        + std::to_string(length - 8U);
    context.add_layer("UDP", bytes, 8U,
        {{"Source port", std::to_string(source_port)},
            {"Destination port", std::to_string(destination_port)},
            {"Length", std::to_string(length)},
            {"Checksum", hex16(bytes.u16(6U))},
            {"Payload length", std::to_string(length - 8U)}});
}

const char* icmpv4_name(const std::uint8_t type)
{
    switch (type) {
    case 0U: return "Echo Reply";
    case 3U: return "Destination Unreachable";
    case 5U: return "Redirect";
    case 8U: return "Echo Request";
    case 11U: return "Time Exceeded";
    case 12U: return "Parameter Problem";
    default: return "ICMP message";
    }
}

void decode_icmpv4(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 8U)) {
        context.fail("short ICMP header");
        return;
    }
    const auto type = bytes.u8(0U);
    Fields fields{{"Type", std::to_string(type)},
        {"Code", std::to_string(bytes.u8(1U))},
        {"Checksum", hex16(bytes.u16(2U))}};
    if (type == 0U || type == 8U) {
        fields.emplace_back("Identifier", std::to_string(bytes.u16(4U)));
        fields.emplace_back("Sequence", std::to_string(bytes.u16(6U)));
    }
    context.packet.info = icmpv4_name(type);
    context.add_layer("ICMP", bytes, 8U, std::move(fields));
}

const char* icmpv6_name(const std::uint8_t type)
{
    switch (type) {
    case 1U: return "Destination Unreachable";
    case 2U: return "Packet Too Big";
    case 3U: return "Time Exceeded";
    case 4U: return "Parameter Problem";
    case 128U: return "Echo Request";
    case 129U: return "Echo Reply";
    case 133U: return "Router Solicitation";
    case 134U: return "Router Advertisement";
    case 135U: return "Neighbor Solicitation";
    case 136U: return "Neighbor Advertisement";
    case 137U: return "Redirect";
    default: return "ICMPv6 message";
    }
}

void decode_icmpv6(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 8U)) {
        context.fail("short ICMPv6 header");
        return;
    }
    const auto type = bytes.u8(0U);
    const auto code = bytes.u8(1U);
    std::size_t header_length = 8U;
    if (type == 134U) header_length = 16U;
    if (type == 135U || type == 136U) header_length = 24U;
    if (type == 137U) header_length = 40U;
    if (!bytes.has(0U, header_length)) {
        context.fail("short ICMPv6 Neighbor Discovery message");
        return;
    }

    Fields fields{{"Type", std::to_string(type)},
        {"Code", std::to_string(code)},
        {"Checksum", hex16(bytes.u16(2U))}};
    context.packet.info = icmpv6_name(type);
    if (type == 128U || type == 129U) {
        fields.emplace_back("Identifier", std::to_string(bytes.u16(4U)));
        fields.emplace_back("Sequence", std::to_string(bytes.u16(6U)));
    }
    if (type == 135U || type == 136U || type == 137U) {
        const auto target = ipv6_address(bytes, 8U);
        fields.emplace_back("Target address", target);
        context.packet.info += " for " + target;
    }
    if (type == 137U) {
        fields.emplace_back("Destination address", ipv6_address(bytes, 24U));
    }
    if (type == 134U) {
        fields.emplace_back("Router lifetime", std::to_string(bytes.u16(6U)));
    }
    context.add_layer("ICMPv6", bytes, header_length, std::move(fields));
}

} // namespace

void decode_ip_payload(DecodeContext& context, const ByteView bytes,
    const std::uint8_t protocol, const bool ipv6)
{
    switch (protocol) {
    case 6U: decode_tcp(context, bytes); return;
    case 17U: decode_udp(context, bytes); return;
    case 1U:
        if (!ipv6) {
            decode_icmpv4(context, bytes);
            return;
        }
        break;
    case 58U:
        if (ipv6) {
            decode_icmpv6(context, bytes);
            return;
        }
        break;
    default: break;
    }
    context.packet.info = (ipv6 ? "IPv6 next header " : "IP protocol ")
        + std::to_string(protocol);
}

} // namespace deep_wire::decoding
