// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, NlasIterator, Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::AmneziaWireguardAttribute;

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WG_FAMILY_NAME: &str = "amneziawg";
const WG_FAMILY_VERSION: u8 = 2;

/* =========================
   CMD
========================= */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardCmd {
    GetDevice,
    SetDevice,
    Other(u8),
}

impl From<AmneziaWireguardCmd> for u8 {
    fn from(cmd: AmneziaWireguardCmd) -> Self {
        match cmd {
            AmneziaWireguardCmd::GetDevice => WG_CMD_GET_DEVICE,
            AmneziaWireguardCmd::SetDevice => WG_CMD_SET_DEVICE,
            AmneziaWireguardCmd::Other(d) => d,
        }
    }
}

impl From<u8> for AmneziaWireguardCmd {
    fn from(v: u8) -> Self {
        match v {
            WG_CMD_GET_DEVICE => Self::GetDevice,
            WG_CMD_SET_DEVICE => Self::SetDevice,
            x => Self::Other(x),
        }
    }
}

/* =========================
   MESSAGE
========================= */

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardMessage {
    pub cmd: AmneziaWireguardCmd,
    pub attributes: Vec<AmneziaWireguardAttribute>,
}

/* =========================
   GenlFamily
========================= */

impl GenlFamily for AmneziaWireguardMessage {
    fn family_name() -> &'static str {
        WG_FAMILY_NAME
    }

    fn version(&self) -> u8 {
        WG_FAMILY_VERSION
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

/* =========================
   EMIT
========================= */

impl Emitable for AmneziaWireguardMessage {
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

/* =========================
   PARSE
========================= */

impl ParseableParametrized<[u8], GenlHeader> for AmneziaWireguardMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}

/* =========================
   ATTRIBUTE PARSER
========================= */

fn parse_attributes(
    buf: &[u8],
) -> Result<Vec<AmneziaWireguardAttribute>, DecodeError> {
    let mut attrs = Vec::new();

    for nla in NlasIterator::new(buf) {
        let nla = nla?;
        attrs.push(AmneziaWireguardAttribute::parse(&nla)?);
    }

    Ok(attrs)
}
