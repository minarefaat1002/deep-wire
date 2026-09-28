#include "packet_decode_internal.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace deep_wire::decoding {

void decode_ethernet(DecodeContext& context, const ByteView bytes)
{
    // Ethernet II starts with destination MAC (bytes 0-5), source MAC
    // (6-11), and a two-byte Type (12-13). A Type of 0x8100 or 0x88a8
    // announces a VLAN tag instead of an immediate IP or ARP payload.
    if (!bytes.has(0U, 14U)) {
        context.fail("short Ethernet header");
        return;
    }

    // Use MAC addresses for the row until a decoded ARP or IP header supplies
    // more useful source and destination addresses.
    context.packet.destination = mac_address(bytes, 0U);
    context.packet.source = mac_address(bytes, 6U);
    std::uint16_t type = bytes.u16(12U);
    context.add_layer("Ethernet", bytes, 14U,
        {{"Destination", context.packet.destination},
            {"Source", context.packet.source},
            {"Type", hex16(type)}});

    // Each VLAN tag adds four bytes: TCI (2) and inner Type (2). The inner
    // Type may announce another VLAN tag, so process tags until it does not.
    std::size_t offset = 14U;
    while (type == 0x8100U || type == 0x88a8U) {
        if (!bytes.has(offset, 4U)) {
            context.fail("short VLAN header");
            return;
        }
        // TCI bits: 15-13 priority, 12 drop eligibility, 11-0 VLAN ID.
        // u16 reads the two wire-order bytes as one host-order value.
        const auto tci = bytes.u16(offset);
        const auto inner_type = bytes.u16(offset + 2U);
        // Record this tag at its absolute frame offset, with display fields.
        context.add_layer("VLAN", bytes.sub(offset, 4U), 4U,
            {{"ID", std::to_string(tci & 0x0fffU)},
                {"Priority", std::to_string(tci >> 13U)},
                {"Drop eligible", (tci & 0x1000U) != 0U ? "yes" : "no"},
                {"Inner type", hex16(inner_type)}});
        type = inner_type;
        offset += 4U;
    }

    // The remaining view starts after Ethernet and all VLAN tags. Its
    // absolute offset lets the next decoder record headers in frame bytes.
    const auto payload = bytes.sub(offset, bytes.data.size() - offset);
    switch (type) {
    case 0x0800U: decode_ipv4(context, payload); return;
    case 0x0806U: decode_arp(context, payload); return;
    case 0x86ddU: decode_ipv6(context, payload); return;
    default:
        // This two-byte field means payload length when it is 0-1500, or a
        // protocol identifier (EtherType) when it is 1536 or higher. Values
        // 1501-1535 are invalid. The supported EtherTypes returned above;
        // keep the raw frame and report other values without decoding them.
        if (type <= 1500U) {
            context.packet.info = "IEEE 802.3 length " + std::to_string(type);
        } else if (type >= 0x0600U) {
            context.packet.info = "EtherType " + hex16(type);
        } else {
            context.packet.info = "Invalid Ethernet length/type " + hex16(type);
        }
        return;
    }
}

} // namespace deep_wire::decoding
