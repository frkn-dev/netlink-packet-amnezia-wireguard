// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the AmneziaWG module
//! loaded and root privileges (CAP_NET_ADMIN).
//!
//! These tests are compiled only on Linux. They will soft-skip themselves
//! when the AmneziaWG family is not available or the process lacks the
//! privileges to create network interfaces.

#![cfg(target_os = "linux")]

use std::process::Command;

use futures::{lock::Mutex, StreamExt};
use genetlink::new_connection;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;

/// Serializes access to netlink interface creation/deletion across tests.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute ip: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("ip {} failed: {}", args.join(" "), stderr))
    }
}

fn delete_interface(name: &str) {
    let _ = run_ip(&["link", "del", name]);
}

fn create_interface(name: &str) -> Result<(), String> {
    delete_interface(name);
    run_ip(&["link", "add", name, "type", "amneziawg"])
}

fn unique_ifname(prefix: &str) -> String {
    format!("{}_{}", prefix, std::process::id())
}

async fn family_available(handle: &mut genetlink::GenetlinkHandle) -> bool {
    handle
        .resolve_family_id::<AmneziaWireguardMessage>()
        .await
        .is_ok()
}

async fn send_request(
    handle: &mut genetlink::GenetlinkHandle,
    msg: AmneziaWireguardMessage,
    flags: u16,
) -> Vec<AmneziaWireguardMessage> {
    let genlmsg: GenlMessage<AmneziaWireguardMessage> =
        GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = flags;

    let mut responses = Vec::new();
    let mut stream = handle.request(nlmsg).await.unwrap();
    while let Some(result) = stream.next().await {
        let rx = result.unwrap();
        match rx.payload {
            NetlinkPayload::InnerMessage(genl) => {
                responses.push(genl.payload);
            }
            NetlinkPayload::Error(e) => {
                panic!("netlink error: {:?}", e.to_io());
            }
            _ => {}
        }
    }
    responses
}

#[tokio::test]
async fn test_get_device_on_amneziawg_interface() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }

    let _guard = TEST_MUTEX.lock().await;

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: amneziawg family not available");
        return;
    }

    let ifname = unique_ifname("awg_get");
    create_interface(&ifname).expect("failed to create test interface");

    let get_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes: vec![AmneziaWireguardAttribute::IfName(ifname.clone())],
    };

    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;

    assert!(
        !responses.is_empty(),
        "expected at least one response for get device"
    );

    let found_name = responses.iter().any(|r| {
        r.attributes.iter().any(|attr| {
            matches!(attr, AmneziaWireguardAttribute::IfName(n) if *n == ifname)
        })
    });
    assert!(found_name, "expected IfName attribute in get response");

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_set_and_get_amnezia_parameters() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }

    let _guard = TEST_MUTEX.lock().await;

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: amneziawg family not available");
        return;
    }

    let ifname = unique_ifname("awg_set");
    create_interface(&ifname).expect("failed to create test interface");

    // SetDevice with Amnezia-specific parameters.
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName(ifname.clone()),
            AmneziaWireguardAttribute::ListenPort(51820),
            AmneziaWireguardAttribute::JC(4),
            AmneziaWireguardAttribute::Jmin(40),
            AmneziaWireguardAttribute::Jmax(70),
            AmneziaWireguardAttribute::S1(92),
            AmneziaWireguardAttribute::S2(115),
            AmneziaWireguardAttribute::S3(44),
            AmneziaWireguardAttribute::S4(9),
            AmneziaWireguardAttribute::H1("61220074".into()),
            AmneziaWireguardAttribute::H2("2351746464".into()),
            AmneziaWireguardAttribute::H3("3053333659".into()),
            AmneziaWireguardAttribute::H4("1789444460".into()),
        ],
    };

    let ack_responses =
        send_request(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await;
    assert!(
        ack_responses.is_empty(),
        "set device with NLM_F_ACK should return no payload on success"
    );

    let get_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes: vec![AmneziaWireguardAttribute::IfName(ifname.clone())],
    };

    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;
    assert_eq!(
        responses.len(),
        1,
        "expected exactly one response for get device"
    );

    let attrs = &responses[0].attributes;
    let listen_port = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::ListenPort(p) = a {
            Some(*p)
        } else {
            None
        }
    });
    assert_eq!(listen_port, Some(51820), "listen port mismatch");

    let jc = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::JC(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jc, Some(4), "JC mismatch");

    let jmin = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::Jmin(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmin, Some(40), "Jmin mismatch");

    let jmax = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::Jmax(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmax, Some(70), "Jmax mismatch");

    let s1 = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::S1(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s1, Some(92), "S1 mismatch");

    let h1 = attrs.iter().find_map(|a| {
        if let AmneziaWireguardAttribute::H1(v) = a {
            Some(v.clone())
        } else {
            None
        }
    });
    assert_eq!(h1, Some("61220074".into()), "H1 mismatch");

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_family_not_available_soft_skip() {
    // This test exercises the soft-skip path on systems without AmneziaWG.
    // When the family is available it still verifies that resolve works.
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let available = family_available(&mut handle).await;
    if !available {
        eprintln!("amneziawg family not available on this system");
    }
    // We cannot assert availability because it depends on the environment.
    // The test simply ensures the resolve call does not panic.
}
