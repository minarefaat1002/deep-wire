#pragma once

#include "packet_decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace deep_wire::decoding {

using Fields = std::vector<std::pair<std::string, std::string>>;

// A bounded view of one section of the captured frame. absolute is its offset
// in Packet::frame.data; subviews keep child decoders within parent lengths.
struct ByteView {
    std::span<const std::uint8_t> data;
    std::size_t absolute{};

    [[nodiscard]] bool has(std::size_t at, std::size_t count) const
    {
        return at <= data.size() && count <= data.size() - at;
    }

    // Decoders check has() before calling these accessors or sub().
    [[nodiscard]] std::uint8_t u8(std::size_t at) const { return data[at]; }
    [[nodiscard]] std::uint16_t u16(std::size_t at) const
    {
        return static_cast<std::uint16_t>(
            (static_cast<unsigned int>(data[at]) << 8U) | data[at + 1U]);
    }
    [[nodiscard]] std::uint32_t u32(std::size_t at) const
    {
        return (static_cast<std::uint32_t>(u16(at)) << 16U) | u16(at + 2U);
    }
    [[nodiscard]] ByteView sub(std::size_t at, std::size_t count) const
    {
        return {data.subspan(at, count), absolute + at};
    }
};

struct DecodeContext {
    Packet& packet;

    void add_layer(std::string name, ByteView bytes,
        std::size_t header_length, Fields fields);
    void fail(std::string message);
};

[[nodiscard]] std::string hex16(std::uint16_t value);
[[nodiscard]] std::string mac_address(ByteView bytes, std::size_t at);
[[nodiscard]] std::string ipv4_address(ByteView bytes, std::size_t at);
[[nodiscard]] std::string ipv6_address(ByteView bytes, std::size_t at);

void decode_ethernet(DecodeContext& context, ByteView bytes);
void decode_arp(DecodeContext& context, ByteView bytes);
void decode_ipv4(DecodeContext& context, ByteView bytes);
void decode_ipv6(DecodeContext& context, ByteView bytes);
void decode_ip_payload(DecodeContext& context, ByteView bytes,
    std::uint8_t protocol, bool ipv6);

} // namespace deep_wire::decoding
