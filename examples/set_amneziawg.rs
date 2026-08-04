// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
use std::{
    convert::TryInto,
    env::args,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[cfg(target_os = "linux")]
use futures::StreamExt;
#[cfg(target_os = "linux")]
use genetlink::new_connection;
#[cfg(target_os = "linux")]
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp,
    AmneziaWireguardAllowedIpAttr, AmneziaWireguardAttribute,
    AmneziaWireguardCmd, AmneziaWireguardMessage, AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute,
};
#[cfg(target_os = "linux")]
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only works on Linux");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: set_amneziawg <ifname>");
        return;
    }

    // The amneziawg interface need to exist before executing this code.
    // This can be done with `ip link <name> type amneziawg` command.
    let name = argv[1].clone();
    let priv_key = generate_priv_key();
    let peer_pub_key: [u8; AmneziaWireguardAttribute::WG_KEY_LEN] =
        base64::decode("8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=")
            .unwrap()
            .try_into()
            .unwrap();

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let attributes = vec![
        AmneziaWireguardAttribute::IfName(name),
        AmneziaWireguardAttribute::PrivateKey(priv_key),
        AmneziaWireguardAttribute::ListenPort(51820),
        AmneziaWireguardAttribute::Fwmark(0),
        // Amnezia specific parameters
        AmneziaWireguardAttribute::JC(4),
        AmneziaWireguardAttribute::Jmin(40),
        AmneziaWireguardAttribute::Jmax(70),
        AmneziaWireguardAttribute::S1(0x5566),
        AmneziaWireguardAttribute::H1("61220074".into()),
        AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
            AmneziaWireguardPeerAttribute::PublicKey(peer_pub_key),
            AmneziaWireguardPeerAttribute::Endpoint(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                51820,
            )),
            AmneziaWireguardPeerAttribute::AllowedIps(vec![
                AmneziaWireguardAllowedIp(vec![
                    // ipv4 0.0.0.0/0
                    AmneziaWireguardAllowedIpAttr::Family(
                        AmneziaWireguardAddressFamily::Ipv4,
                    ),
                    AmneziaWireguardAllowedIpAttr::IpAddr(
                        "0.0.0.0".parse().unwrap(),
                    ),
                    AmneziaWireguardAllowedIpAttr::Cidr(0),
                ]),
                AmneziaWireguardAllowedIp(vec![
                    // ipv6 ::/0
                    AmneziaWireguardAllowedIpAttr::Family(
                        AmneziaWireguardAddressFamily::Ipv6,
                    ),
                    AmneziaWireguardAllowedIpAttr::IpAddr(
                        "::".parse().unwrap(),
                    ),
                    AmneziaWireguardAllowedIpAttr::Cidr(0),
                ]),
            ]),
        ])]),
    ];

    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes,
    };

    let genlmsg: GenlMessage<AmneziaWireguardMessage> =
        GenlMessage::from_payload(msg);

    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut res = handle.request(nlmsg).await.unwrap();

    if let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        if let NetlinkPayload::Error(e) = rx_packet.payload {
            eprintln!("Error: {:?}", e.to_io());
        }
    }
}

#[cfg(target_os = "linux")]
fn generate_priv_key() -> [u8; AmneziaWireguardAttribute::WG_KEY_LEN] {
    let mut key = [0u8; AmneziaWireguardAttribute::WG_KEY_LEN];
    getrandom::getrandom(&mut key).unwrap();
    // modify random bytes using algorithm described
    // at https://cr.yp.to/ecdh.html.
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}
