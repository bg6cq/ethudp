# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

```bash
# Build with debug symbols
make

# Build with optimization (-O2)
make run

# Re-indent source code (uses GNU indent)
make indent

# Clean binary
rm -f EthUDP
```

**Dependencies:** `openssl-devel lz4-devel libpcap-devel` (CentOS) or `libssl-dev liblz4-dev libpcap-dev` (Debian).

The build is a single-file compile with no test suite, no CI, and no static analysis tools configured.

## Code Architecture

**Single-file C program** (`EthUDP.c`, ~2044 lines) — no separate headers, no object files, no library. Compiled into one binary `EthUDP`.

### Operating Modes

The program bridges Layer 2 Ethernet segments over UDP. Five modes controlled by CLI flags:

| Mode | Flag | Input Source | Packet Type | Notes |
|------|------|-------------|-------------|-------|
| Raw Ether Bridge | `-e` | Raw socket on eth\* | Full Ethernet frames | 802.1Q auxdata for VLAN stripping/insertion |
| Tap Interface | `-i` | TUN/TAP char device | L2 frames | Creates a `tap` interface, assigns IP |
| Bridge | `-b` | TUN/TAP char device | L2 frames | Creates a `tap`, adds to `brctl` bridge |
| Full Packet Capture | `-t` | libpcap | Full Ethernet frames | Read-only; supports pcap filter |
| UDP Packet Capture | `-u` | libpcap | UDP payload only | Extracts UDP payload, sends to remote |

### Threading Model

Three pthreads + main thread:

1. **Main thread** — runs `process_raw_to_udp()`: reads packets from local interface (raw socket, TUN/TAP, or pcap), optionally encrypts/compresses, sends to remote via UDP.
2. **Master UDP receiver** — runs `process_udp_to_raw_master()`: receives UDP packets from master remote, decrypts/decompresses, writes to local interface.
3. **Slave UDP receiver** (optional) — runs `process_udp_to_raw_slave()`: same as above but for the failover connection.
4. **Keepalive thread** — runs `send_keepalive_to_udp()`: sends PING every second, tracks PONG responses, detects master/slave status (3-second window: BAD→OK after 1 PONG within 4 ticks, OK→BAD after 5 missed PONGs).

### Data Flow

```
Local Interface → [LZ4 Compress] → [Encrypt] → UDP Socket → Remote
                                                              
Remote → UDP Socket → [Decrypt] → [LZ4 Decompress] → Local Interface
```

Encryption pipeline: LZ4 compression first (with marker byte 0xFF for compressed, 0xAA for not), then encryption (XOR or AES-CBC).

### Key Features

- **Encryption:** XOR or AES-128/192/256 (OpenSSL EVP, CBC mode). If `-enc` set without `-k`, defaults to key `"123456"`. If `-k` set without `-enc`, defaults to AES-128.
- **Compression:** LZ4 with acceleration 0–9 (0 = disabled). Stores a trailing marker byte (0xFF compressed, 0xAA not).
- **Master/Slave failover:** Two UDP connections; switches to slave when master misses 5 PONGs. Default 1-second PING interval.
- **NAT traversal:** When remote address is `0.0.0.0:0`, binds without `connect()`, uses `sendto`/`recvfrom`, updates remote address on first valid packet. Optional password-based authentication for security.
- **UDP fragmentation:** `-mtu` flag splits packets > MTU-28 into two UDPFRG segments (max 1000+ bytes each), reassembled by sequence number pairs. Uses `packet_bufs[MAXPKTS]` ring buffer.
- **VLAN mapping:** `-map vlanmap.txt` translates 802.1Q VID between local and remote VLANs.
- **TCP MSS fix:** `-mss` flag rewrites TCP SYN MSS option (IPv4 and IPv6), will never increase MSS.
- **Loopback prevention:** Detects packets whose src/dst IP matches the remote UDP endpoint to prevent routing loops.
- **Statistics:** SIGHUP prints stats; SIGUSR1 resets counters. Hourly stats logged automatically.
- **Benchmark mode:** `-B` runs encryption/compression benchmark (300k packets).
- **Auto-restart:** When not in debug mode, daemonizes and forks — parent waits for child, respawns after 2 seconds on crash.

### Globals & Concurrency Globals

All state is in global variables (no context struct). Thread-safe because:
- Each thread reads from its own fd set (raw socket, master UDP, slave UDP)
- Shared counters (`udp_total`, `compress_save`, `encrypt_overhead`, etc.) are `volatile` but NOT atomics — benign races on statistics only
- `volatile sig_atomic_t got_signal` for signal handler
- `remote_addr[2]` is `volatile` — updated by UDP receiver threads, read by keepalive and sender thread
- `myticket` and `last_pong[2]` are `volatile unsigned long`

### Network Details

- **Raw socket:** `PF_PACKET, SOCK_RAW, ETH_P_ALL` with promiscuous mode, `PACKET_AUXDATA` for VLAN tag extraction via `recvmsg`
- **UDP socket:** `SOCK_DGRAM`, receive buffer set to 10MB, `IP_MTU_DISCOVER` disabled (DF bit cleared)
- **TUN/TAP:** Opens `/dev/net/tun`, IFF_TAP with IFF_NO_PI, configures via `system()` calls to `ip` and `brctl`
- **Jumbo frames:** MAX_PACKET_SIZE = 9234 bytes

### Packet Structures

- `_EtherHeader` — packed struct for Ethernet frame parsing (dest MAC, src MAC, VLAN tag, EtherType, payload)
- `vlan_tag` — 4-byte VLAN tag (TPID + TCI) for auxdata reconstruction
- `packet_buf` — UDP fragment reassembly buffer with timestamp and sequence number