#include "packet_decode_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace deep_wire::decoding {
namespace {

bool is_ipv6_extension(const std::uint8_t next)
{
    return next == 0U || next == 43U || next == 44U
        || next == 51U || next == 60U;
}

const char* extension_name(const std::uint8_t next)
{
    switch (next) {
    case 0U: return "IPv6 Hop-by-Hop";
    case 43U: return "IPv6 Routing";
    case 44U: return "IPv6 Fragment";
    case 51U: return "IPv6 Authentication";
    default: return "IPv6 Destination Options";
    }
}

} // namespace

void decode_ipv4(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 20U)) {
        context.fail("short IPv4 header");
        return;
    }
    const auto version = bytes.u8(0U) >> 4U;
    const auto header_length =
        static_cast<std::size_t>(bytes.u8(0U) & 0x0fU) * 4U;
    if (version != 4U || header_length < 20U
        || !bytes.has(0U, header_length)) {
        context.fail("invalid or short IPv4 header");
        return;
    }
    const auto total_length = static_cast<std::size_t>(bytes.u16(2U));
    if (total_length < header_length) {
        context.fail("IPv4 total length is smaller than its header");
        return;
    }

    const auto source = ipv4_address(bytes, 12U);
    const auto destination = ipv4_address(bytes, 16U);
    const auto protocol = bytes.u8(9U);
    const auto fragment = bytes.u16(6U);
    context.packet.source = source;
    context.packet.destination = destination;
    context.add_layer("IPv4", bytes, header_length,
        {{"Source", source}, {"Destination", destination},
            {"Header length", std::to_string(header_length)},
            {"Total length", std::to_string(total_length)},
            {"TTL", std::to_string(bytes.u8(8U))},
            {"Protocol number", std::to_string(protocol)},
            {"Identification", std::to_string(bytes.u16(4U))},
            {"Fragment offset", std::to_string(fragment & 0x1fffU)},
            {"Header checksum", hex16(bytes.u16(10U))}});
    if (!bytes.has(0U, total_length)) {
        context.fail("truncated IPv4 packet");
        return;
    }
    if ((fragment & 0x3fffU) != 0U) {
        context.packet.info = "IPv4 fragment; transport decoding deferred";
        return;
    }

    decode_ip_payload(context,
        bytes.sub(header_length, total_length - header_length),
        protocol, false);
}

void decode_ipv6(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 40U)) {
        context.fail("short IPv6 header");
        return;
    }
    if ((bytes.u8(0U) >> 4U) != 6U) {
        context.fail("invalid IPv6 version");
        return;
    }

    const auto payload_length = static_cast<std::size_t>(bytes.u16(4U));
    const auto first_word = bytes.u32(0U);
    auto next = bytes.u8(6U);
    const auto source = ipv6_address(bytes, 8U);
    const auto destination = ipv6_address(bytes, 24U);
    context.packet.source = source;
    context.packet.destination = destination;
    context.add_layer("IPv6", bytes, 40U,
        {{"Source", source}, {"Destination", destination},
            {"Traffic class", std::to_string((first_word >> 20U) & 0xffU)},
            {"Flow label", std::to_string(first_word & 0xfffffU)},
            {"Payload length", std::to_string(payload_length)},
            {"Next header", std::to_string(next)},
            {"Hop limit", std::to_string(bytes.u8(7U))}});
    if (payload_length == 0U) {
        context.packet.info = bytes.data.size() > 40U
            ? "IPv6 jumbogram not decoded" : "No IPv6 payload";
        return;
    }
    if (!bytes.has(40U, payload_length)) {
        context.fail("truncated IPv6 packet");
        return;
    }

    auto payload = bytes.sub(40U, payload_length);
    std::size_t extension_count{};
    while (is_ipv6_extension(next)) {
        if (++extension_count > 32U) {
            context.fail("too many IPv6 extension headers");
            return;
        }
        const auto current = next;
        if (!payload.has(0U, 2U)) {
            context.fail("short IPv6 extension header");
            return;
        }
        next = payload.u8(0U);
        std::size_t length{};
        if (current == 44U) {
            length = 8U;
        } else if (current == 51U) {
            length = (static_cast<std::size_t>(payload.u8(1U)) + 2U) * 4U;
            if (length < 12U) {
                context.fail("invalid IPv6 authentication header length");
                return;
            }
        } else {
            length = (static_cast<std::size_t>(payload.u8(1U)) + 1U) * 8U;
        }
        if (!payload.has(0U, length)) {
            context.fail("truncated IPv6 extension header");
            return;
        }

        Fields fields{{"Next header", std::to_string(next)},
            {"Length", std::to_string(length)}};
        if (current == 44U) {
            const auto fragment = payload.u16(2U);
            fields.emplace_back("Fragment offset",
                std::to_string((fragment & 0xfff8U) >> 3U));
            fields.emplace_back("More fragments",
                (fragment & 1U) != 0U ? "yes" : "no");
            fields.emplace_back("Identification",
                std::to_string(payload.u32(4U)));
            context.packet.layers.push_back(
                {extension_name(current), payload.absolute,
                    length, std::move(fields)});
            if ((fragment & 0xfff9U) != 0U) {
                context.packet.info =
                    "IPv6 fragment; transport decoding deferred";
                return;
            }
        } else {
            context.packet.layers.push_back(
                {extension_name(current), payload.absolute,
                    length, std::move(fields)});
        }
        payload = payload.sub(length, payload.data.size() - length);
    }

    if (next == 59U) {
        context.packet.info = "No next header";
    } else if (next == 50U) {
        context.packet.info = "Encrypted ESP payload";
    } else {
        decode_ip_payload(context, payload, next, true);
    }
}

} // namespace deep_wire::decoding
