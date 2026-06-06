// SPDX-License-Identifier: MIT

use std::env::args;

use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr, AmneziaWireguardAttribute,
    AmneziaWireguardCmd, AmneziaWireguardMessage, AmneziaWireguardPeerAttribute,
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_amneziawg_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes: vec![AmneziaWireguardAttribute::IfName(argv[1].clone())],
    };

    let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut res = handle.request(nlmsg).await.unwrap();

    while let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }
}

fn print_wg_payload(wg: AmneziaWireguardMessage) {
    for attr in &wg.attributes {
        match attr {
            AmneziaWireguardAttribute::IfIndex(v) => println!("IfIndex: {}", v),
            AmneziaWireguardAttribute::IfName(v) => println!("IfName: {}", v),
            AmneziaWireguardAttribute::PrivateKey(_) => {
                println!("PrivateKey: (hidden)")
            }
            AmneziaWireguardAttribute::PublicKey(v) => {
                println!("PublicKey: {}", base64::encode(v))
            }
            AmneziaWireguardAttribute::ListenPort(v) => {
                println!("ListenPort: {}", v)
            }
            AmneziaWireguardAttribute::Fwmark(v) => println!("Fwmark: {}", v),
            AmneziaWireguardAttribute::Peers(peers) => {
                for peer in peers {
                    println!("Peer: ");
                    print_wg_peer(&peer);
                }
            }
            AmneziaWireguardAttribute::JC(v) => {
                println!("JunkCount: {}", v)
            }
            AmneziaWireguardAttribute::Jmin(v) => {
                println!("JunkPacketMinSize: {}", v)
            }
            AmneziaWireguardAttribute::Jmax(v) => {
                println!("JunkPacketMaxSize: {}", v)
            }
            _ => (),
        }
    }
}

fn print_wg_peer(attrs: &[AmneziaWireguardPeerAttribute]) {
    for attr in attrs {
        match attr {
            AmneziaWireguardPeerAttribute::PublicKey(v) => {
                println!("  PublicKey: {}", base64::encode(v))
            }
            AmneziaWireguardPeerAttribute::PresharedKey(_) => {
                println!("  PresharedKey: (hidden)")
            }
            AmneziaWireguardPeerAttribute::Endpoint(v) => {
                println!("  Endpoint: {}", v)
            }
            AmneziaWireguardPeerAttribute::PersistentKeepalive(v) => {
                println!("  PersistentKeepalive: {}", v)
            }
            AmneziaWireguardPeerAttribute::LastHandshake(v) => {
                println!("  LastHandshake: {:?}", v)
            }
            AmneziaWireguardPeerAttribute::RxBytes(v) => println!("  RxBytes: {}", v),
            AmneziaWireguardPeerAttribute::TxBytes(v) => println!("  TxBytes: {}", v),
            AmneziaWireguardPeerAttribute::AllowedIps(ips) => {
                for ip in ips {
                    print_wg_allowedip(&ip);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_allowedip(nlas: &AmneziaWireguardAllowedIp) -> Option<()> {
    let ipaddr = nlas.iter().find_map(|nla| {
        if let AmneziaWireguardAllowedIpAttr::IpAddr(addr) = nla {
            Some(*addr)
        } else {
            None
        }
    })?;
    let cidr = nlas.iter().find_map(|nla| {
        if let AmneziaWireguardAllowedIpAttr::Cidr(cidr) = nla {
            Some(*cidr)
        } else {
            None
        }
    })?;
    println!("  AllowedIp: {}/{}", ipaddr, cidr);
    Some(())
}
