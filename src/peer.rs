// SPDX-License-Identifier: MIT

use std::{convert::TryInto, net::SocketAddr};

use netlink_packet_core::{
    emit_i64, emit_u16, emit_u32, emit_u64, parse_i64, parse_u16, parse_u32,
    parse_u64, DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use super::{
    allowedip::AmneziaWireguardAllowedIps,
    socket_addr::{
        emit_socket_addr, parse_socket_addr, SOCKET_ADDR_V4_LEN,
        SOCKET_ADDR_V6_LEN,
    },
};
use crate::AmneziaWireguardAllowedIp;

pub(crate) struct AmneziaWireguardPeers(pub(crate) Vec<AmneziaWireguardPeer>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardPeers
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(AmneziaWireguardPeer::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl std::ops::Deref for AmneziaWireguardPeers {
    type Target = Vec<AmneziaWireguardPeer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardPeer(pub Vec<AmneziaWireguardPeerAttribute>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardPeer
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(AmneziaWireguardPeerAttribute::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl Nla for AmneziaWireguardPeer {
    fn kind(&self) -> u16 {
        // linux kernel always set it to 0
        NLA_F_NESTED
    }

    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }
}

impl std::ops::Deref for AmneziaWireguardPeer {
    type Target = Vec<AmneziaWireguardPeerAttribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const TIMESPEC_LEN: usize = 16;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardTimeSpec {
    pub seconds: i64,
    pub nano_seconds: i64,
}

impl Emitable for AmneziaWireguardTimeSpec {
    fn buffer_len(&self) -> usize {
        TIMESPEC_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_i64(&mut buffer[..8], self.seconds).unwrap();
        emit_i64(&mut buffer[8..16], self.nano_seconds).unwrap();
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardTimeSpec
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let data = buf.value();
        if data.len() < TIMESPEC_LEN {
            Err(format!(
                "Invalid WGPEER_A_LAST_HANDSHAKE_TIME, expecting size {}, but \
                 got {:?}",
                TIMESPEC_LEN, data
            )
            .into())
        } else {
            Ok(Self {
                seconds: parse_i64(&data[..8])?,
                nano_seconds: parse_i64(&data[8..16])?,
            })
        }
    }
}

const NOISE_PUBLIC_KEY_LEN: usize = 32;
const NOISE_SYMMETRIC_KEY_LEN: usize = 32;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardPeerAttribute {
    PublicKey([u8; NOISE_PUBLIC_KEY_LEN]),
    PresharedKey([u8; NOISE_SYMMETRIC_KEY_LEN]),
    Endpoint(SocketAddr),
    /// Persistent keepalive interval in seconds.
    ///
    /// Emitted as `u16`, understood by kernel modules up to genl family
    /// version 2 (v1.0.20260725). When parsing, a 2-byte payload produces
    /// this variant.
    PersistentKeepalive(u16),
    /// Persistent keepalive as `u32` packing a `u16` range
    /// (`lo | hi << 16`), the wire format of the AmneziaWG 3.0 kernel
    /// module (genl family version 3). Produced by parsing 4-byte
    /// payloads; a plain interval `v` sent by new tools arrives as
    /// `v | v << 16`.
    PersistentKeepaliveRange(u32),
    LastHandshake(AmneziaWireguardTimeSpec),
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<AmneziaWireguardAllowedIp>),
    ProtocolVersion(u32),
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for AmneziaWireguardPeerAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::PublicKey(v) => size_of_val(v),
            Self::PresharedKey(v) => size_of_val(v),
            Self::Endpoint(v) => match *v {
                SocketAddr::V4(_) => SOCKET_ADDR_V4_LEN,
                SocketAddr::V6(_) => SOCKET_ADDR_V6_LEN,
            },
            Self::PersistentKeepalive(v) => size_of_val(v),
            Self::PersistentKeepaliveRange(v) => size_of_val(v),
            Self::LastHandshake(v) => v.buffer_len(),
            Self::RxBytes(v) => size_of_val(v),
            Self::TxBytes(v) => size_of_val(v),
            Self::AllowedIps(v) => v.as_slice().buffer_len(),
            Self::ProtocolVersion(v) => size_of_val(v),
            Self::Flags(v) => size_of_val(v),
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::PublicKey(_) => WGPEER_A_PUBLIC_KEY,
            Self::PresharedKey(_) => WGPEER_A_PRESHARED_KEY,
            Self::Endpoint(_) => WGPEER_A_ENDPOINT,
            Self::PersistentKeepalive(_)
            | Self::PersistentKeepaliveRange(_) => {
                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL
            }
            Self::LastHandshake(_) => WGPEER_A_LAST_HANDSHAKE_TIME,
            Self::RxBytes(_) => WGPEER_A_RX_BYTES,
            Self::TxBytes(_) => WGPEER_A_TX_BYTES,
            Self::AllowedIps(_) => WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            Self::ProtocolVersion(_) => WGPEER_A_PROTOCOL_VERSION,
            Self::Flags(_) => WGPEER_A_FLAGS,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::PublicKey(v) => buffer.copy_from_slice(v),
            Self::PresharedKey(v) => buffer.copy_from_slice(v),
            Self::Endpoint(v) => emit_socket_addr(v, buffer),
            Self::PersistentKeepalive(v) => emit_u16(buffer, *v).unwrap(),
            Self::PersistentKeepaliveRange(v) => emit_u32(buffer, *v).unwrap(),
            Self::LastHandshake(v) => v.emit(buffer),
            Self::RxBytes(v) => emit_u64(buffer, *v).unwrap(),
            Self::TxBytes(v) => emit_u64(buffer, *v).unwrap(),
            Self::AllowedIps(v) => v.as_slice().emit(buffer),
            Self::ProtocolVersion(v) => emit_u32(buffer, *v).unwrap(),
            Self::Flags(v) => emit_u32(buffer, *v).unwrap(),
            Self::Other(v) => v.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardPeerAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGPEER_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGPEER_A_PUBLIC_KEY")?,
            ),
            WGPEER_A_PRESHARED_KEY => Self::PresharedKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGPEER_A_PRESHARED_KEY")?,
            ),
            WGPEER_A_ENDPOINT => Self::Endpoint(
                parse_socket_addr(payload)
                    .context("invalid WGPEER_A_ENDPOINT")?,
            ),
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                // AmneziaWG 3.0 sends a u32 (packed u16 range), older
                // modules send a u16.
                match payload.len() {
                    2 => {
                        Self::PersistentKeepalive(parse_u16(payload).context(
                            "invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL \
                             value",
                        )?)
                    }
                    4 => Self::PersistentKeepaliveRange(
                        parse_u32(payload).context(
                            "invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL \
                             value",
                        )?,
                    ),
                    _ => {
                        return Err(DecodeError::from(format!(
                            "invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL \
                             payload length {}",
                            payload.len()
                        )))
                    }
                }
            }
            WGPEER_A_LAST_HANDSHAKE_TIME => Self::LastHandshake(
                AmneziaWireguardTimeSpec::parse(buf)
                    .context("invalid WGPEER_A_LAST_HANDSHAKE_TIME")?,
            ),
            WGPEER_A_RX_BYTES => Self::RxBytes(
                parse_u64(payload)
                    .context("invalid WGPEER_A_RX_BYTES value")?,
            ),
            WGPEER_A_TX_BYTES => Self::TxBytes(
                parse_u64(payload)
                    .context("invalid WGPEER_A_TX_BYTES value")?,
            ),
            WGPEER_A_ALLOWEDIPS => {
                Self::AllowedIps(AmneziaWireguardAllowedIps::parse(buf)?.0)
            }
            WGPEER_A_PROTOCOL_VERSION => Self::ProtocolVersion(
                parse_u32(payload)
                    .context("invalid WGPEER_A_PROTOCOL_VERSION value")?,
            ),
            WGPEER_A_FLAGS => Self::Flags(
                parse_u32(payload).context("invalid WGPEER_A_FLAGS value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
