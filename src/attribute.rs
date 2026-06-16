// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use netlink_packet_core::{
    emit_u16, emit_u32, parse_string, parse_u16, parse_u32, DecodeError,
    DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer, Parseable,
    NLA_F_NESTED,
};

use super::peer::AmneziaWireguardPeers;
use crate::AmneziaWireguardPeer;

const WG_KEY_LEN: usize = 32;

const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

/// Amnezia Flags
const WGDEVICE_A_JC: u16 = 9;
const WGDEVICE_A_JMIN: u16 = 10;
const WGDEVICE_A_JMAX: u16 = 11;
const WGDEVICE_A_S1: u16 = 12;
const WGDEVICE_A_S2: u16 = 13;
const WGDEVICE_A_H1: u16 = 14;
const WGDEVICE_A_H2: u16 = 15;
const WGDEVICE_A_H3: u16 = 16;
const WGDEVICE_A_H4: u16 = 17;
const WGDEVICE_A_PEER: u16 = 18;
const WGDEVICE_A_S3: u16 = 19;
const WGDEVICE_A_S4: u16 = 20;
const WGDEVICE_A_I1: u16 = 21;
const WGDEVICE_A_I2: u16 = 22;
const WGDEVICE_A_I3: u16 = 23;
const WGDEVICE_A_I4: u16 = 24;
const WGDEVICE_A_I5: u16 = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardAttribute {
    IfIndex(u32),
    IfName(String),
    PrivateKey([u8; WG_KEY_LEN]),
    PublicKey([u8; WG_KEY_LEN]),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<AmneziaWireguardPeer>),
    Flags(u32),
    // Amnezia attributes
    Peer(AmneziaWireguardPeer),
    JC(u16),   // JunkCount
    Jmin(u16), // JunkPacketMinSize
    Jmax(u16), // JunkPacketMaxSize
    S1(u16),
    S2(u16),
    /// Magic header spec, e.g. `"61220074"` or `"684141592-1751861769"`.
    H1(String),
    H2(String),
    H3(String),
    H4(String),
    S3(u16),
    S4(u16),
    /// Intermediate header descriptor string.
    I1(String),
    I2(String),
    I3(String),
    I4(String),
    I5(String),
    Other(DefaultNla),
}

impl AmneziaWireguardAttribute {
    pub const WG_KEY_LEN: usize = WG_KEY_LEN;
}

impl Nla for AmneziaWireguardAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::IfName(v)
            | Self::H1(v)
            | Self::H2(v)
            | Self::H3(v)
            | Self::H4(v)
            | Self::I1(v)
            | Self::I2(v)
            | Self::I3(v)
            | Self::I4(v)
            | Self::I5(v) => v.len() + 1,
            Self::PrivateKey(_) | Self::PublicKey(_) => WG_KEY_LEN,
            Self::ListenPort(_) => 2,
            Self::Peers(v) => v.as_slice().buffer_len(),
            Self::Fwmark(_) | Self::IfIndex(_) | Self::Flags(_) => 4,
            // Amnezia Specific Fields
            Self::Peer(v) => v.buffer_len(),
            Self::JC(_)
            | Self::Jmax(_)
            | Self::Jmin(_)
            | Self::S1(_)
            | Self::S2(_)
            | Self::S3(_)
            | Self::S4(_) => 2,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::IfIndex(_) => WGDEVICE_A_IFINDEX,
            Self::IfName(_) => WGDEVICE_A_IFNAME,
            Self::PrivateKey(_) => WGDEVICE_A_PRIVATE_KEY,
            Self::PublicKey(_) => WGDEVICE_A_PUBLIC_KEY,
            Self::ListenPort(_) => WGDEVICE_A_LISTEN_PORT,
            Self::Fwmark(_) => WGDEVICE_A_FWMARK,
            Self::Peers(_) => WGDEVICE_A_PEERS | NLA_F_NESTED,
            Self::Flags(_) => WGDEVICE_A_FLAGS,
            // Amnezia Specific
            Self::Peer(_) => WGDEVICE_A_PEER | NLA_F_NESTED,
            Self::JC(_) => WGDEVICE_A_JC,
            Self::Jmin(_) => WGDEVICE_A_JMIN,
            Self::Jmax(_) => WGDEVICE_A_JMAX,
            Self::S1(_) => WGDEVICE_A_S1,
            Self::S2(_) => WGDEVICE_A_S2,
            Self::H1(_) => WGDEVICE_A_H1,
            Self::H2(_) => WGDEVICE_A_H2,
            Self::H3(_) => WGDEVICE_A_H3,
            Self::H4(_) => WGDEVICE_A_H4,
            Self::S3(_) => WGDEVICE_A_S3,
            Self::S4(_) => WGDEVICE_A_S4,
            Self::I1(_) => WGDEVICE_A_I1,
            Self::I2(_) => WGDEVICE_A_I2,
            Self::I3(_) => WGDEVICE_A_I3,
            Self::I4(_) => WGDEVICE_A_I4,
            Self::I5(_) => WGDEVICE_A_I5,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(v) => emit_u32(buffer, *v).unwrap(),
            Self::IfName(s)
            | Self::H1(s)
            | Self::H2(s)
            | Self::H3(s)
            | Self::H4(s)
            | Self::I1(s)
            | Self::I2(s)
            | Self::I3(s)
            | Self::I4(s)
            | Self::I5(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::PrivateKey(v) => buffer.copy_from_slice(v),
            Self::PublicKey(v) => buffer.copy_from_slice(v),
            Self::ListenPort(v) => emit_u16(buffer, *v).unwrap(),
            Self::Fwmark(v) => emit_u32(buffer, *v).unwrap(),
            Self::Peers(v) => v.as_slice().emit(buffer),
            Self::Flags(v) => emit_u32(buffer, *v).unwrap(),
            // Amnezia Specific
            Self::Peer(v) => v.emit(buffer),
            Self::JC(v)
            | Self::Jmin(v)
            | Self::Jmax(v)
            | Self::S1(v)
            | Self::S2(v)
            | Self::S3(v)
            | Self::S4(v) => emit_u16(buffer, *v).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGDEVICE_A_IFINDEX => Self::IfIndex(
                parse_u32(payload)
                    .context("invalid WGDEVICE_A_IFINDEX value")?,
            ),
            WGDEVICE_A_IFNAME => Self::IfName(
                parse_string(payload)
                    .context("invalid WGDEVICE_A_IFNAME value")?,
            ),
            WGDEVICE_A_PRIVATE_KEY => Self::PrivateKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGDEVICE_A_PRIVATE_KEY value")?,
            ),
            WGDEVICE_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGDEVICE_A_PUBLIC_KEY value")?,
            ),
            WGDEVICE_A_LISTEN_PORT => Self::ListenPort(
                parse_u16(payload)
                    .context("invalid WGDEVICE_A_LISTEN_PORT value")?,
            ),
            WGDEVICE_A_FWMARK => Self::Fwmark(
                parse_u32(payload)
                    .context("invalid WGDEVICE_A_FWMARK value")?,
            ),
            WGDEVICE_A_PEERS => {
                Self::Peers(AmneziaWireguardPeers::parse(buf)?.0)
            }
            WGDEVICE_A_FLAGS => Self::Flags(
                parse_u32(payload).context("invalid WGDEVICE_A_FLAGS value")?,
            ),
            WGDEVICE_A_PEER => Self::Peer(AmneziaWireguardPeer::parse(buf)?),
            WGDEVICE_A_JC => Self::JC(
                parse_u16(payload).context("invalid WGDEVICE_A_JC value")?,
            ),
            WGDEVICE_A_JMIN => Self::Jmin(
                parse_u16(payload).context("invalid WGDEVICE_A_JMIN value")?,
            ),
            WGDEVICE_A_JMAX => Self::Jmax(
                parse_u16(payload).context("invalid WGDEVICE_A_JMAX value")?,
            ),
            WGDEVICE_A_S1 => Self::S1(
                parse_u16(payload).context("invalid WGDEVICE_A_S1 value")?,
            ),
            WGDEVICE_A_S2 => Self::S2(
                parse_u16(payload).context("invalid WGDEVICE_A_S2 value")?,
            ),
            WGDEVICE_A_H1 => Self::H1(
                parse_string(payload).context("invalid WGDEVICE_A_H1 value")?,
            ),
            WGDEVICE_A_H2 => Self::H2(
                parse_string(payload).context("invalid WGDEVICE_A_H2 value")?,
            ),
            WGDEVICE_A_H3 => Self::H3(
                parse_string(payload).context("invalid WGDEVICE_A_H3 value")?,
            ),
            WGDEVICE_A_H4 => Self::H4(
                parse_string(payload).context("invalid WGDEVICE_A_H4 value")?,
            ),
            WGDEVICE_A_S3 => Self::S3(
                parse_u16(payload).context("invalid WGDEVICE_A_S3 value")?,
            ),
            WGDEVICE_A_S4 => Self::S4(
                parse_u16(payload).context("invalid WGDEVICE_A_S4 value")?,
            ),
            WGDEVICE_A_I1 => Self::I1(
                parse_string(payload).context("invalid WGDEVICE_A_I1 value")?,
            ),
            WGDEVICE_A_I2 => Self::I2(
                parse_string(payload).context("invalid WGDEVICE_A_I2 value")?,
            ),
            WGDEVICE_A_I3 => Self::I3(
                parse_string(payload).context("invalid WGDEVICE_A_I3 value")?,
            ),
            WGDEVICE_A_I4 => Self::I4(
                parse_string(payload).context("invalid WGDEVICE_A_I4 value")?,
            ),
            WGDEVICE_A_I5 => Self::I5(
                parse_string(payload).context("invalid WGDEVICE_A_I5 value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
