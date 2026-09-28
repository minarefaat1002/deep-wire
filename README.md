# Deep Wire

Deep Wire is a Linux packet sniffer written in C++20. It captures link-layer
frames directly with an `AF_PACKET` raw socket; it does not use libpcap.

## Current command-line version

The executable lists interfaces, captures a requested number of frames,
records kernel timestamps and captured/original lengths, and prints a decoded
summary for each frame. It keeps the raw bytes and the decoded header fields,
offsets, and lengths in one `Packet`.

The current decoder recognizes:

| Ethernet payload | Decoded headers |
|---|---|
| `0x0800` | IPv4, then TCP, UDP, or ICMPv4 |
| `0x0806` | ARP, including Ethernet/IPv4 requests and replies |
| `0x86DD` | IPv6, then TCP, UDP, or ICMPv6 |
| `0x8100`, `0x88A8` | One or more VLAN tags, followed by their inner EtherType |

ICMPv6 summaries recognize echo and Neighbor Discovery messages (router
solicitation/advertisement, neighbor solicitation/advertisement, and redirect).
The IPv6 decoder follows Hop-by-Hop, Routing, Destination Options, Fragment,
and Authentication extension headers to find the next protocol.

## Decoder architecture

```text
CaptureEngine -> CapturedFrame -> PacketDecoder
                                  |
                                  Ethernet -> optional VLAN tags
                                           -> ARP
                                           -> IPv4 -> TCP / UDP / ICMPv4
                                           -> IPv6 -> extension headers
                                                   -> TCP / UDP / ICMPv6
```

`packet_decoder.cpp` contains the public decode entry point. The
`packet_decode_internal.hpp/.cpp` pair holds the shared byte view, layer
recording, and address formatting helpers. Each protocol decoder checks its
header, adds a `DecodedLayer` with fields and absolute byte offsets, and
dispatches using the protocol number in that header. A bounded byte view
limits child decoders to the length declared by their parent. Unknown protocols retain the
raw bytes and a numeric type. Truncated or malformed headers produce a
`Packet.error` instead of an out-of-bounds read.

Decoding stops at IPv4 and IPv6 fragments that require reassembly. IPv6
jumbograms, encrypted ESP payloads, and unknown extension headers are not
decoded further. Neighbor Discovery options and checksums are not validated.
TCP stream reassembly, HTTP, DNS, filters, PCAP files, and the Qt GUI are later
milestones.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

## List interfaces

```bash
./build/deep-wire --list
```

## Capture frames

Opening an `AF_PACKET` raw socket requires `CAP_NET_RAW`. Run only the
compiled executable with appropriate privileges:

```bash
sudo ./build/deep-wire wlp0s20f3 10
```

Or grant that capability to the executable:

```bash
sudo setcap cap_net_raw=eip ./build/deep-wire
./build/deep-wire wlp0s20f3 10
```

Rebuilding the executable may remove its file capability. Do not run the IDE
or the entire build process as root.
