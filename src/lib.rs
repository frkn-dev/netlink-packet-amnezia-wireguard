// SPDX-License-Identifier: MIT

//! The `netlink-packet-amnezia-wireguard` crate is designed for parsing and
//! emitting generic netlink packets for Amnezia WireGuard interface.

mod allowedip;
mod attribute;
mod message;
mod peer;
mod socket_addr;

#[cfg(test)]
mod test;

pub use self::{
    allowedip::{
        AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    },
    attribute::AmneziaWireguardAttribute,
    message::{AmneziaWireguardCmd, AmneziaWireguardMessage},
    peer::{AmneziaWireguardPeer, AmneziaWireguardPeerAttribute, AmneziaWireguardTimeSpec},
};
