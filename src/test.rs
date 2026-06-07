// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};

use netlink_packet_core::{Emitable, Parseable, ParseableParametrized};
use netlink_packet_generic::{GenlBuffer, GenlHeader};
use pretty_assertions::assert_eq;

use crate::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp,
    AmneziaWireguardAllowedIpAttr, AmneziaWireguardAttribute,
    AmneziaWireguardCmd, AmneziaWireguardMessage, AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute, AmneziaWireguardTimeSpec,
};

fn roundtrip_msg(msg: AmneziaWireguardMessage) -> AmneziaWireguardMessage {
    let header = GenlHeader {
        cmd: msg.cmd.into(),
        version: 2,
    };
    let header_len = header.buffer_len();
    let mut buffer = vec![0; msg.buffer_len() + header_len];
    header.emit(&mut buffer);
    msg.emit(&mut buffer[header_len..]);
    AmneziaWireguardMessage::parse_with_param(&buffer[header_len..], header)
        .unwrap()
}

// nlmon capture of netlink packet sent by `sudo wg` command with netlink
// header purged(generic netlink command is first byte).
#[test]
fn test_query_request() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
    ];

    let expected: AmneziaWireguardMessage = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes: vec![AmneziaWireguardAttribute::IfName("cn".to_string())],
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        AmneziaWireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );
    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

// nlmon capture of kernel netlink packet reply of `sudo wg` command with
// netlink header purged(generic netlink command is first byte).
//  * private key is masked to vec![01..31]
//  * ip address is masked to 1.1.1.1:1111
#[test]
fn test_query_reply() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x2c, 0x80, 0x00, 0x00,
        0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
        0x24, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x24, 0x00, 0x04, 0x00, 0xcc, 0xaf, 0x10, 0xe1, 0xa9, 0xd7, 0xd0, 0x5f,
        0xf2, 0xbd, 0xd2, 0xa0, 0xf1, 0x78, 0x2d, 0x97, 0x46, 0x9a, 0x1c, 0xf7,
        0xbe, 0x88, 0x0f, 0x68, 0x75, 0xa7, 0x79, 0x93, 0x5d, 0x1d, 0x21, 0x75,
        0xc0, 0x00, 0x08, 0x80, 0xbc, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00,
        0x77, 0xdc, 0x9a, 0xc0, 0xb3, 0xf0, 0xc5, 0xe7, 0x5b, 0xb8, 0xd3, 0x42,
        0x2d, 0x88, 0xec, 0x92, 0xd1, 0x3a, 0x34, 0x23, 0x22, 0x90, 0x87, 0x82,
        0x15, 0x51, 0x57, 0x19, 0x69, 0xde, 0xa0, 0x44, 0x24, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00,
        0x9a, 0x24, 0x77, 0x69, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xa8, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x19, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x80, 0x40, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x98, 0x44, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x04, 0x57, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x09, 0x80, 0x1c, 0x00, 0x00, 0x80,
        0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let attributes = vec![
        AmneziaWireguardAttribute::ListenPort(32812),
        AmneziaWireguardAttribute::Fwmark(0),
        AmneziaWireguardAttribute::IfIndex(3),
        AmneziaWireguardAttribute::IfName("cn".to_string()),
        AmneziaWireguardAttribute::PrivateKey([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        AmneziaWireguardAttribute::PublicKey([
            204, 175, 16, 225, 169, 215, 208, 95, 242, 189, 210, 160, 241, 120,
            45, 151, 70, 154, 28, 247, 190, 136, 15, 104, 117, 167, 121, 147,
            93, 29, 33, 117,
        ]),
        AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
            AmneziaWireguardPeerAttribute::PublicKey([
                119, 220, 154, 192, 179, 240, 197, 231, 91, 184, 211, 66, 45,
                136, 236, 146, 209, 58, 52, 35, 34, 144, 135, 130, 21, 81, 87,
                25, 105, 222, 160, 68,
            ]),
            AmneziaWireguardPeerAttribute::PresharedKey([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            AmneziaWireguardPeerAttribute::LastHandshake(
                AmneziaWireguardTimeSpec {
                    seconds: 1769415834,
                    nano_seconds: 262671874,
                },
            ),
            AmneziaWireguardPeerAttribute::PersistentKeepalive(25),
            AmneziaWireguardPeerAttribute::TxBytes(1917056),
            AmneziaWireguardPeerAttribute::RxBytes(30426264),
            AmneziaWireguardPeerAttribute::ProtocolVersion(1),
            AmneziaWireguardPeerAttribute::Endpoint(
                std::net::SocketAddr::from_str("1.1.1.1:1111").unwrap(),
            ),
            AmneziaWireguardPeerAttribute::AllowedIps(vec![
                AmneziaWireguardAllowedIp(vec![
                    AmneziaWireguardAllowedIpAttr::Cidr(0),
                    AmneziaWireguardAllowedIpAttr::Family(
                        AmneziaWireguardAddressFamily::Ipv4,
                    ),
                    AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                        Ipv4Addr::UNSPECIFIED,
                    )),
                ]),
            ]),
        ])]),
    ];

    let expected: AmneziaWireguardMessage = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes,
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        AmneziaWireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

#[test]
fn test_amnezia_junk_parameters() {
    // Message with Amnezia Specific Junk params
    let msg: AmneziaWireguardMessage = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName("awg0".into()),
            AmneziaWireguardAttribute::JC(4),
            AmneziaWireguardAttribute::Jmin(40),
            AmneziaWireguardAttribute::Jmax(70),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // Checking Amnezia Specific bytes
    // JunkCount (JC) should be 11 (0x0b)
    // Netlink Attribute: [Length (2 bytes), Type (2 bytes), Value (n bytes)]

    assert!(
        buffer
            .windows(6)
            .any(|w| w == [0x06, 0x00, 0x09, 0x00, 0x04, 0x00]),
        "JC failed"
    );

    assert!(
        buffer
            .windows(6)
            .any(|w| w == [0x06, 0x00, 0x0a, 0x00, 0x28, 0x00]),
        "Jmin failed"
    );
}

#[test]
fn test_amnezia_magic_headers() {
    let msg: AmneziaWireguardMessage = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::H1(0x1122), // u16
            AmneziaWireguardAttribute::S1(0x5566), // u16
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // H1 (type 14 / 0x0e, lenght 6): [06, 00, 0e, 00, 22, 11]
    assert!(buffer
        .windows(6)
        .any(|w| w == [0x06, 0x00, 0x0e, 0x00, 0x22, 0x11]));

    // S1 (type 12 / 0x0c, length 6): [06, 00, 0c, 00, 66, 55]
    assert!(buffer
        .windows(6)
        .any(|w| w == [0x06, 0x00, 0x0c, 0x00, 0x66, 0x55]));
}

#[test]
fn test_set_device_roundtrip() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName("awg0".into()),
            AmneziaWireguardAttribute::ListenPort(51820),
            AmneziaWireguardAttribute::Fwmark(1234),
            AmneziaWireguardAttribute::Flags(1),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_all_amnezia_attributes_emit_and_roundtrip() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::JC(1),
            AmneziaWireguardAttribute::Jmin(10),
            AmneziaWireguardAttribute::Jmax(100),
            AmneziaWireguardAttribute::S1(0x0102),
            AmneziaWireguardAttribute::S2(0x0304),
            AmneziaWireguardAttribute::S3(0x0506),
            AmneziaWireguardAttribute::S4(0x0708),
            AmneziaWireguardAttribute::H1(0x1111),
            AmneziaWireguardAttribute::H2(0x2222),
            AmneziaWireguardAttribute::H3(0x3333),
            AmneziaWireguardAttribute::H4(0x4444),
            AmneziaWireguardAttribute::I1(0xaaaa),
            AmneziaWireguardAttribute::I2(0xbbbb),
            AmneziaWireguardAttribute::I3(0xcccc),
            AmneziaWireguardAttribute::I4(0xdddd),
            AmneziaWireguardAttribute::I5(0xeeee),
            AmneziaWireguardAttribute::DataInit(100),
            AmneziaWireguardAttribute::DataResponse(200),
            AmneziaWireguardAttribute::DataConfirm(300),
            AmneziaWireguardAttribute::DataTransport(400),
        ],
    };

    let parsed = roundtrip_msg(msg.clone());
    assert_eq!(msg, parsed);
}

#[test]
fn test_allowed_ips_ipv6_roundtrip() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey([42u8; 32]),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(
                            AmneziaWireguardAddressFamily::Ipv6,
                        ),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V6(
                            Ipv6Addr::UNSPECIFIED,
                        )),
                        AmneziaWireguardAllowedIpAttr::Cidr(0),
                    ]),
                ]),
            ]),
        ])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_multiple_allowed_ips_per_peer() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey([7u8; 32]),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(
                            AmneziaWireguardAddressFamily::Ipv4,
                        ),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                            Ipv4Addr::new(10, 0, 0, 0),
                        )),
                        AmneziaWireguardAllowedIpAttr::Cidr(8),
                    ]),
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(
                            AmneziaWireguardAddressFamily::Ipv6,
                        ),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V6(
                            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                        )),
                        AmneziaWireguardAllowedIpAttr::Cidr(128),
                    ]),
                ]),
            ]),
        ])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_peer_with_endpoint_keepalive_and_flags() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey([1u8; 32]),
                AmneziaWireguardPeerAttribute::PresharedKey([2u8; 32]),
                AmneziaWireguardPeerAttribute::Endpoint(SocketAddr::V6(
                    SocketAddrV6::new(
                        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                        51820,
                        0,
                        0,
                    ),
                )),
                AmneziaWireguardPeerAttribute::PersistentKeepalive(25),
                AmneziaWireguardPeerAttribute::Flags(
                    crate::constants::WGPEER_F_REPLACE_ALLOWEDIPS,
                ),
            ]),
        ])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_empty_peers_roundtrip() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName("awg0".into()),
            AmneziaWireguardAttribute::Peers(vec![]),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_full_device_config_roundtrip() {
    let private_key: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    let public_key: [u8; 32] = [
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
        13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ];

    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfIndex(5),
            AmneziaWireguardAttribute::IfName("awg0".into()),
            AmneziaWireguardAttribute::PrivateKey(private_key),
            AmneziaWireguardAttribute::PublicKey(public_key),
            AmneziaWireguardAttribute::ListenPort(51820),
            AmneziaWireguardAttribute::Fwmark(0),
            AmneziaWireguardAttribute::Flags(
                crate::constants::WGDEVICE_F_REPLACE_PEERS,
            ),
            // Amnezia parameters
            AmneziaWireguardAttribute::JC(4),
            AmneziaWireguardAttribute::Jmin(40),
            AmneziaWireguardAttribute::Jmax(70),
            AmneziaWireguardAttribute::S1(0x1234),
            AmneziaWireguardAttribute::S2(0x5678),
            AmneziaWireguardAttribute::H1(0x9abc),
            AmneziaWireguardAttribute::H2(0xdef0),
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey([0xabu8; 32]),
                AmneziaWireguardPeerAttribute::Endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    51820,
                )),
                AmneziaWireguardPeerAttribute::PersistentKeepalive(25),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(
                            AmneziaWireguardAddressFamily::Ipv4,
                        ),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                            Ipv4Addr::new(0, 0, 0, 0),
                        )),
                        AmneziaWireguardAllowedIpAttr::Cidr(0),
                    ]),
                ]),
            ])]),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}
