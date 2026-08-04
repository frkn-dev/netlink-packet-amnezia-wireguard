# netlink-packet-amnezia-wireguard

[![Crates.io](https://img.shields.io/crates/v/netlink-packet-amnezia-wireguard)](https://crates.io/crates/netlink-packet-amnezia-wireguard)
[![Docs.rs](https://docs.rs/netlink-packet-amnezia-wireguard/badge.svg)](https://docs.rs/netlink-packet-amnezia-wireguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust crate for parsing and emitting **Amnezia WireGuard** generic netlink packets on Linux.

This is a specialized fork focused specifically on **AmneziaWG** kernel module support.  
For plain WireGuard, use the original [`netlink-packet-wireguard`](https://crates.io/crates/netlink-packet-wireguard) crate.

## What is AmneziaWG?

[AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) is a fork of WireGuard that adds junk-packet padding and magic headers to mask WireGuard traffic from Deep Packet Inspection (DPI). This crate allows you to configure AmneziaWG interfaces via the kernel netlink API the same way `wg` / `awg` tools do.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
netlink-packet-amnezia-wireguard = "0.2"
```

## Quick Start

### Get device info

```rust
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};

let msg = AmneziaWireguardMessage {
    cmd: AmneziaWireguardCmd::GetDevice,
    attributes: vec![AmneziaWireguardAttribute::IfName("awg0".into())],
};
```

### Set device with Amnezia-specific parameters

```rust
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAddressFamily,
    AmneziaWireguardAllowedIp,
    AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute,
    AmneziaWireguardCmd,
    AmneziaWireguardMessage,
    AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

let msg = AmneziaWireguardMessage {
    cmd: AmneziaWireguardCmd::SetDevice,
    attributes: vec![
        AmneziaWireguardAttribute::IfName("awg0".into()),
        AmneziaWireguardAttribute::ListenPort(51820),
        // AmneziaWG-specific junk packet settings
        AmneziaWireguardAttribute::JC(4),
        AmneziaWireguardAttribute::Jmin(40),
        AmneziaWireguardAttribute::Jmax(70),
        AmneziaWireguardAttribute::S1(0x5566),
        AmneziaWireguardAttribute::H1("61220074".into()),
        AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(peer_pub_key),
                AmneziaWireguardPeerAttribute::Endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                    51820,
                )),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(
                            AmneziaWireguardAddressFamily::Ipv4,
                        ),
                        AmneziaWireguardAllowedIpAttr::IpAddr("0.0.0.0".parse().unwrap()),
                        AmneziaWireguardAllowedIpAttr::Cidr(0),
                    ]),
                ]),
            ]),
        ]),
    ],
};
```

### Full examples

See the [`examples/`](./examples) directory for complete async programs using `genetlink` and `tokio`.

```bash
cargo run --example get_amneziawg_info -- awg0
cargo run --example set_amneziawg -- awg0
```

## Supported attributes

In addition to standard WireGuard attributes (`PrivateKey`, `PublicKey`, `Peers`, `ListenPort`, etc.), the following AmneziaWG-specific fields are supported:

| Attribute | Description |
|-----------|-------------|
| `JC` | Junk packet count |
| `Jmin` | Junk packet minimum size |
| `Jmax` | Junk packet maximum size |
| `S1` … `S4` | Junk packet sizes (`u16`) |
| `H1` … `H4` | Magic header specs (`String`, e.g. `"61220074"` or `"684141592-1751861769"`). Emitted as strings for kernel modules up to v1.0 (genl version 2); all wire formats are normalized into these variants when parsing |
| `H1Range` … `H4Range` | Magic headers as packed `u64` ranges (`lo \| hi << 32`), the AmneziaWG 3.0 wire format (genl version 3). Use `range::u32_range_from_string` to build them from spec strings |
| `I1` … `I5` | Intermediate header descriptors (`String`)|
| `HeaderProtectionKey` | AmneziaWG 3.0 header protection key (32 bytes) |
| `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` | AmneziaWG 3.0 tuning knobs (`u32`) |

Peer attributes: `PersistentKeepalive(u16)` is the pre-3.0 wire format, while
AmneziaWG 3.0 sends a `u32` (packed `u16` range), parsed into
`PersistentKeepaliveRange(u32)`.
## License

This project is licensed under the [MIT License](./LICENSE).

## Acknowledgements

Based on the original [`netlink-packet-wireguard`](https://github.com/rust-netlink/netlink-packet-wireguard) crate by the rust-netlink team.
