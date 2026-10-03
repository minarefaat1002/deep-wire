# Deep Wire

Deep Wire is a Linux packet sniffer written in C++20. It captures link-layer
frames directly with an `AF_PACKET` raw socket; it does not use libpcap.

## Capture and decoding

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
TCP stream reassembly, HTTP, DNS, display filters, and PCAP files are later
milestones. Capture currently accepts Ethernet-style interfaces, including
managed Wi-Fi and Linux loopback. Other link types are rejected explicitly.

## Desktop GUI

The Qt 6 interface provides:

- Interface selection, refresh, Start, Stop, and a configurable packet limit.
- A packet table with number, UTC kernel timestamp, source, destination,
  protocol, original frame length, and protocol-specific info.
- Expandable Frame metadata and decoded protocol layers for the selected row.
- Original hexadecimal/ASCII bytes; selecting a layer highlights its header.
  Selecting a display field highlights its containing header.
- Inline capture errors, including missing raw-socket permissions.

Each Start replaces the previous capture and resets frame numbering. Stop
retains received packets for inspection. Capture also stops at the selected
packet limit (100,000 by default); this is a packet count limit, not a RAM
budget. Details remain available when capture ends or an interface fails.

### GUI structure

```text
Background thread                      GUI thread
CaptureEngine -> PacketDecoder         PacketTableModel -> QTableView
               -> bounded handoff  ->                    -> PacketDetails
                  (256 packets)           drain every 50 ms
```

`CaptureSession` owns a C++20 `std::jthread`. It receives and decodes frames,
then moves them into a mutex-protected, bounded handoff queue. A GUI timer
transfers each batch into `PacketTableModel`, which owns the stored packets.
Qt models and widgets are accessed only from the GUI thread. Stop and window
closure request cancellation; a 100 ms socket wait bounds idle shutdown.
A full handoff queue pauses the worker until the GUI consumes it; the kernel
socket can still drop packets during sustained overload.

| File | Responsibility |
|---|---|
| `gui_main.cpp` | Start the Qt application |
| `main_window.hpp/.cpp` | Capture controls, packet table, and batch delivery |
| `capture_session.hpp/.cpp` | Background capture/decoding and cancellation |
| `packet_table_model.hpp/.cpp` | Retain packets and expose summary columns |
| `packet_details.hpp/.cpp` | Expandable layer fields and byte highlighting |

## Build

Install a C++20 compiler, CMake, and the Qt 6 Widgets development package.
On Ubuntu/Debian:

```bash
sudo apt install build-essential cmake qt6-base-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

This builds `deep-wire` (CLI) and `deep-wire-gui` (desktop), sharing the
`deep-wire-core` capture/decoder library. For a Qt-free CLI build:

```bash
cmake -S . -B build-cli -DDEEP_WIRE_BUILD_GUI=OFF
cmake --build build-cli --parallel
```

## Launch the GUI

Opening an `AF_PACKET` raw socket requires `CAP_NET_RAW`. Grant it to the
compiled GUI executable, then launch the window as your normal user:

```bash
sudo setcap cap_net_raw=eip ./build/deep-wire-gui
./build/deep-wire-gui
```

The window opens without that capability, but Start reports a permission
error. Select an interface, choose a packet limit, and press Start. Generate
traffic on that interface (for example, `ping -c 3 127.0.0.1` with `lo`
selected). Click a row, expand a layer, and select it to highlight its bytes.
Use Stop to finish early.

Rebuilding may remove the executable's capability; grant it again as needed.
Do not run the IDE or the entire build process as root.

## CLI

```bash
./build/deep-wire --list
sudo ./build/deep-wire wlp0s20f3 10
```

Or grant `CAP_NET_RAW` to `deep-wire` and capture as your normal user:

```bash
sudo setcap cap_net_raw=eip ./build/deep-wire
./build/deep-wire wlp0s20f3 10
```
