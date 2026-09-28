#pragma once

#include "captured_frame.hpp"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace deep_wire {

// One decoded protocol layer. Offset and length identify its bytes within
// Packet::frame.data. For example, TCP can start at byte 34 and use 20 bytes
// after a 14-byte Ethernet header and a 20-byte IPv4 header.
struct DecodedLayer {
    std::string name;
    std::size_t offset{};
    std::size_t length{};
    // Display name/value pairs, e.g. {"Source port", "12345"} for TCP.
    std::vector<std::pair<std::string, std::string>> fields;
};

// One captured frame with its decoded layers and a short display summary.
struct Packet {
    // Owns the captured bytes and metadata. When nonempty, frame.data[0]
    // is the first byte of the captured frame.
    CapturedFrame frame;
    // All recognized layers, in wire order. Example: Ethernet, IPv4, TCP.
    // A VLAN-tagged frame can instead have Ethernet, VLAN, IPv4, TCP.
    std::vector<DecodedLayer> layers;

    // One address pair chosen for the summary row. These duplicate values in
    // layers: Ethernet MACs initially, replaced by IP addresses when decoded
    // (or sender/target IPs for supported ARP). For an IPv4 frame, these
    // might be "192.0.2.1" and "198.51.100.2" while the Ethernet layer still
    // holds its MAC addresses. Empty if Ethernet is too short.
    std::string source;
    std::string destination;
    // Example row: protocol "TCP" and info "12345 -> 80 [SYN] Len=0".
    // On a bad frame, error might be "short Ethernet header".
    std::string protocol{"Unknown"};
    std::string info;
    std::string error;
};

// Entry point: keep the captured frame and decode its protocol layers.
// Example: Packet packet = PacketDecoder::decode(std::move(frame));
class PacketDecoder {
public:
    [[nodiscard]] static Packet decode(CapturedFrame frame);
};

} // namespace deep_wire
