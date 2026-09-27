#pragma once

#include "captured_frame.hpp"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace deep_wire {

struct DecodedLayer {
    std::string name;
    std::size_t offset{};
    std::size_t length{};
    std::vector<std::pair<std::string, std::string>> fields;
};

struct Packet {
    CapturedFrame frame;
    std::vector<DecodedLayer> layers;
    std::string source;
    std::string destination;
    std::string protocol{"Unknown"};
    std::string info;
    std::string error;
};

class PacketParser {
public:
    [[nodiscard]] static Packet parse(CapturedFrame frame);
};

} // namespace deep_wire
