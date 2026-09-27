# Deep Wire

Deep Wire is a Linux packet sniffer written in C++20. It captures link-layer
frames directly with an `AF_PACKET` raw socket; it does not use libpcap.

## Current command-line version

The current executable can:

- list the available network interfaces;
- bind a raw packet socket to one selected interface;
- obtain nanosecond kernel timestamps;
- retain captured and original frame lengths; and
- capture a requested number of frames and stop cleanly; and
- decode Ethernet, VLAN, IPv4, TCP, and UDP headers in the terminal.

HTTP, DNS, filters, PCAP files, and the Qt GUI are planned for later phases.
The current parser checks header lengths and reports malformed or truncated
packets; checksum validation and fragment reassembly are still to come.

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

Opening an `AF_PACKET` raw socket requires `CAP_NET_RAW`. Either run only the
compiled executable with appropriate privileges:

```bash
sudo ./build/deep-wire wlp0s20f3 10
```

or grant that capability to the executable:

```bash
sudo setcap cap_net_raw=eip ./build/deep-wire
./build/deep-wire wlp0s20f3 10
```

Rebuilding the executable may remove its file capability. Do not run the IDE
or the entire build process as root.
