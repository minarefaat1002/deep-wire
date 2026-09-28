#include "packet_decode_internal.hpp"

#include <cstddef>
#include <string>
#include <utility>

namespace deep_wire::decoding {

void decode_arp(DecodeContext& context, const ByteView bytes)
{
    if (!bytes.has(0U, 8U)) {
        context.fail("short ARP header");
        return;
    }

    const auto hardware_type = bytes.u16(0U);
    const auto protocol_type = bytes.u16(2U);
    const auto hardware_length = static_cast<std::size_t>(bytes.u8(4U));
    const auto protocol_length = static_cast<std::size_t>(bytes.u8(5U));
    const auto opcode = bytes.u16(6U);
    if (hardware_length == 0U || protocol_length == 0U) {
        context.fail("invalid ARP address length");
        return;
    }

    // Four variable-length addresses follow the fixed eight-byte header.
    const auto length = 8U + 2U * hardware_length + 2U * protocol_length;
    if (!bytes.has(0U, length)) {
        context.fail("truncated ARP addresses");
        return;
    }

    Fields fields{
        {"Hardware type", std::to_string(hardware_type)},
        {"Protocol type", hex16(protocol_type)},
        {"Hardware length", std::to_string(hardware_length)},
        {"Protocol length", std::to_string(protocol_length)},
        {"Opcode", std::to_string(opcode)}
    };

    if (hardware_type == 1U && protocol_type == 0x0800U
        && hardware_length == 6U && protocol_length == 4U) {
        const auto sender_mac = mac_address(bytes, 8U);
        const auto sender_ip = ipv4_address(bytes, 14U);
        const auto target_mac = mac_address(bytes, 18U);
        const auto target_ip = ipv4_address(bytes, 24U);
        fields.emplace_back("Sender MAC", sender_mac);
        fields.emplace_back("Sender IP", sender_ip);
        fields.emplace_back("Target MAC", target_mac);
        fields.emplace_back("Target IP", target_ip);
        context.packet.source = sender_ip;
        context.packet.destination = target_ip;
        if (opcode == 1U) {
            context.packet.info = "Who has " + target_ip + "? Tell " + sender_ip;
        } else if (opcode == 2U) {
            context.packet.info = sender_ip + " is at " + sender_mac;
        }
    }
    if (context.packet.info.empty()) {
        context.packet.info = "ARP opcode " + std::to_string(opcode);
    }
    context.add_layer("ARP", bytes, length, std::move(fields));
}

} // namespace deep_wire::decoding
