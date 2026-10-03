#pragma once

// Shared implementation helpers for the Ethernet, ARP, IP, and transport
// decoders. Application code uses PacketDecoder from packet_decoder.hpp.

#include "packet_decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace deep_wire::decoding {

// Ordered display name/value pairs stored in a DecodedLayer, for example
// {{"Source port", "12345"}, {"Destination port", "80"}}.
using Fields = std::vector<std::pair<std::string, std::string>>;

// A non-owning view of one section of Packet::frame.data. The frame's storage
// must remain valid and must not be reallocated while a view is in use.
// Offsets passed to methods are relative to this view; absolute locates its
// first byte in the original frame. Child views limit the bytes available to
// the next decoder, for example to an IP packet's declared payload length.
struct ByteView {
    std::span<const std::uint8_t> data;
    std::size_t absolute{};

    // Whether [at, at + count) fits in this view. Subtraction avoids overflow
    // from adding untrusted offsets and lengths. An empty range at the end fits.
    [[nodiscard]] bool has(std::size_t at, std::size_t count) const
    {
        return at <= data.size() && count <= data.size() - at;
    }

    // Read one byte. The caller must first establish has(at, 1).
    [[nodiscard]] std::uint8_t u8(std::size_t at) const { return data[at]; }

    // Read a network-order (big-endian) 16-bit integer as a numeric value.
    // Requires has(at, 2); no alignment or host byte-order assumption is needed.
    [[nodiscard]] std::uint16_t u16(std::size_t at) const
    {
        return static_cast<std::uint16_t>(
            (static_cast<unsigned int>(data[at]) << 8U) | data[at + 1U]);
    }

    // Read a network-order 32-bit integer. Requires has(at, 4).
    [[nodiscard]] std::uint32_t u32(std::size_t at) const
    {
        return (static_cast<std::uint32_t>(u16(at)) << 16U) | u16(at + 2U);
    }

    // Select a child range without copying bytes. Requires has(at, count).
    // For example, skipping a 14-byte Ethernet header in a view at absolute
    // offset 0 gives a payload view at absolute offset 14.
    [[nodiscard]] ByteView sub(std::size_t at, std::size_t count) const
    {
        return {data.subspan(at, count), absolute + at};
    }
};

// Mutable state shared by every decoder handling the same captured frame.
// The referenced Packet must outlive the context. Decoders use it to record
// layers and update source, destination, protocol, info, and error summaries.
struct DecodeContext {
    Packet& packet;

    // Append a layer at bytes.absolute, with header_length bytes and display
    // fields, then set packet.protocol to name. The caller validates that the
    // header fits in bytes; the recorded length excludes trailing payload.
    void add_layer(std::string name, ByteView bytes,
        std::size_t header_length, Fields fields);

    // Replace packet.error with message, preserving layers already decoded.
    // This does not throw or stop decoding itself; callers return as needed.
    void fail(std::string message);
};

// Format a 16-bit value with a 0x prefix and four lowercase hexadecimal digits,
// for example hex16(0x0800) == "0x0800".
[[nodiscard]] std::string hex16(std::uint16_t value);

// Format six bytes as a colon-separated MAC address. Requires bytes.has(at, 6).
[[nodiscard]] std::string mac_address(ByteView bytes, std::size_t at);

// Format four bytes as a dotted-decimal IPv4 address. Requires bytes.has(at, 4).
[[nodiscard]] std::string ipv4_address(ByteView bytes, std::size_t at);

// Format sixteen bytes using inet_ntop's IPv6 notation. Requires bytes.has(at,
// 16); returns "<invalid IPv6 address>" if conversion fails.
[[nodiscard]] std::string ipv6_address(ByteView bytes, std::size_t at);

// Each decoder receives a view starting at its protocol header, validates
// lengths before reading, and records errors in context.packet. A malformed
// inner header can leave previously decoded outer layers in the result.

// Decode Ethernet and any stacked VLAN tags, then dispatch by the final Type
// to ARP, IPv4, or IPv6. Other Type/length values produce a summary only.
void decode_ethernet(DecodeContext& context, ByteView bytes);

// Decode ARP's fixed header and variable-length address area. Ethernet/IPv4
// ARP also supplies sender/target addresses and request/reply summaries.
void decode_arp(DecodeContext& context, ByteView bytes);

// Decode IPv4 and restrict transport decoding to its declared total length.
// Fragmented packets are summarized without decoding their transport headers.
void decode_ipv4(DecodeContext& context, ByteView bytes);

// Decode IPv6 and supported extension headers within its declared payload.
// Fragmented packets, ESP payloads, and jumbograms are not decoded further.
void decode_ipv6(DecodeContext& context, ByteView bytes);

// Dispatch an already bounded IP payload: protocol is the IPv4 Protocol or
// final IPv6 Next Header value. ipv6 selects ICMPv4 versus ICMPv6 handling;
// TCP and UDP work for either version. Unsupported values produce a summary.
void decode_ip_payload(DecodeContext& context, ByteView bytes,
    std::uint8_t protocol, bool ipv6);

} // namespace deep_wire::decoding
