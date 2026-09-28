#include "packet_decoder.hpp"
#include "packet_decode_internal.hpp"

#include <cstdint>
#include <span>
#include <utility>

namespace deep_wire {

Packet PacketDecoder::decode(CapturedFrame frame)
{
    // The returned Packet owns the received bytes and capture metadata.
    // Moving frame avoids another copy of its byte vector.
    Packet packet;
    packet.frame = std::move(frame);

    // Decoders use context to add layers, choose summary fields, or set an
    // error on this same packet; context does not make a second Packet.
    decoding::DecodeContext context{packet};

    // ByteView reads packet.frame.data without copying it. Its absolute
    // offset starts at zero; child views keep offsets in the original frame.
    const decoding::ByteView bytes{
        std::span<const std::uint8_t>{packet.frame.data}, 0U};

    // Ethernet is the outermost header. Its Type, or the final inner Type
    // after VLAN tags, selects ARP, IPv4, or IPv6. For Ethernet/IPv4/TCP,
    // the decoders can record layer offsets 0, 14, and 34 respectively.
    decoding::decode_ethernet(context, bytes);
    return packet;
}

} // namespace deep_wire
