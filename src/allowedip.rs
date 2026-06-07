// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    emit_u16, parse_ip, parse_u16, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

pub(crate) struct AmneziaWireguardAllowedIps(
    pub(crate) Vec<AmneziaWireguardAllowedIp>,
);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardAllowedIps
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(AmneziaWireguardAllowedIp::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl std::ops::Deref for AmneziaWireguardAllowedIps {
    type Target = Vec<AmneziaWireguardAllowedIp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardAllowedIp(pub Vec<AmneziaWireguardAllowedIpAttr>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardAllowedIp
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(AmneziaWireguardAllowedIpAttr::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl Nla for AmneziaWireguardAllowedIp {
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

impl std::ops::Deref for AmneziaWireguardAllowedIp {
    type Target = Vec<AmneziaWireguardAllowedIpAttr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const AF_INET6: u16 = 10;
const AF_INET: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardAddressFamily {
    Ipv4,
    Ipv6,
    Other(u16),
}

impl From<u16> for AmneziaWireguardAddressFamily {
    fn from(d: u16) -> Self {
        match d {
            AF_INET6 => Self::Ipv6,
            AF_INET => Self::Ipv4,
            _ => Self::Other(d),
        }
    }
}

impl From<AmneziaWireguardAddressFamily> for u16 {
    fn from(v: AmneziaWireguardAddressFamily) -> u16 {
        match v {
            AmneziaWireguardAddressFamily::Ipv6 => AF_INET6,
            AmneziaWireguardAddressFamily::Ipv4 => AF_INET,
            AmneziaWireguardAddressFamily::Other(d) => d,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardAllowedIpAttr {
    Family(AmneziaWireguardAddressFamily),
    IpAddr(IpAddr),
    Cidr(u8),
    Other(DefaultNla),
}

impl Nla for AmneziaWireguardAllowedIpAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Family(_) => 2,
            Self::IpAddr(v) => match *v {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
            Self::Cidr(_) => 1,
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Family(_) => WGALLOWEDIP_A_FAMILY,
            Self::IpAddr(_) => WGALLOWEDIP_A_IPADDR,
            Self::Cidr(_) => WGALLOWEDIP_A_CIDR_MASK,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Family(v) => emit_u16(buffer, u16::from(*v)).unwrap(),
            Self::IpAddr(ip) => match ip {
                IpAddr::V4(ip) => buffer.copy_from_slice(&ip.octets()),
                IpAddr::V6(ip) => buffer.copy_from_slice(&ip.octets()),
            },
            Self::Cidr(v) => buffer[0] = *v,
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AmneziaWireguardAllowedIpAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGALLOWEDIP_A_FAMILY => Self::Family(
                parse_u16(payload)
                    .context("invalid WGALLOWEDIP_A_FAMILY value")?
                    .into(),
            ),
            WGALLOWEDIP_A_IPADDR => Self::IpAddr(
                parse_ip(payload)
                    .context("invalid WGALLOWEDIP_A_IPADDR value")?,
            ),
            WGALLOWEDIP_A_CIDR_MASK => Self::Cidr(payload[0]),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
