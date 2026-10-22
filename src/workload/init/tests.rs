use super::*;
use crate::platform::uds::UdsStream;
use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope};
use std::{
    io::{Read, Write},
    time::Duration,
};

#[test]
fn captured_init_is_root_scoped_ordered_and_stops_before_the_next_command() {
    let (client, mut peer) = UdsStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server = std::thread::spawn(move || {
        for index in 0..2 {
            let mut length = [0; 4];
            peer.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            peer.read_exact(&mut bytes).unwrap();
            let envelope: Envelope<AgentRequest> = serde_json::from_slice(&bytes).unwrap();
            match envelope.body {
                AgentRequest::Run {
                    image,
                    command,
                    user,
                    mounts,
                    persistent_overlay_id,
                    interactive,
                    detached,
                    ..
                } => {
                    // AgentClient canonicalizes image aliases before sending the request.
                    assert_eq!(image, "docker.io/library/example:latest");
                    assert_eq!(command, argv(&format!("step{index}")));
                    assert_eq!(user.as_deref(), Some("0"));
                    assert_eq!(persistent_overlay_id.as_deref(), Some("example"));
                    assert_eq!(mounts.len(), 1);
                    assert_eq!(mounts[0].1, "/data");
                    assert!(!interactive && !detached);
                }
                other => panic!("unexpected init request: {other:?}"),
            }
            peer.write_all(
                &encode_message(&AgentResponse::Completed {
                    exit_code: if index == 0 { 0 } else { 7 },
                    stdout: Vec::new(),
                    stderr: b"synthetic refusal".to_vec(),
                })
                .unwrap(),
            )
            .unwrap();
        }
        let mut next = [0; 4];
        assert_eq!(
            peer.read(&mut next).unwrap(),
            0,
            "failure does not issue another command"
        );
    });
    let mut client = AgentClient::from_stream(client);
    let result = run(
        &mut client,
        &["step0".into(), "step1".into(), "must-not-run".into()],
        Context {
            image: Some("example:latest"),
            image_info: None,
            env: &[],
            workdir: None,
            record_mounts: &[("/host/source".into(), "/data".into(), false)],
            overlay_id: "example",
        },
        false,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("init[1] failed (exit 7)"));
    drop(client);
    server.join().unwrap();
}

#[test]
fn bare_init_and_image_init_share_the_same_failure_contract() {
    let (client, mut peer) = UdsStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        let mut length = [0; 4];
        peer.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        peer.read_exact(&mut bytes).unwrap();
        let envelope: Envelope<AgentRequest> = serde_json::from_slice(&bytes).unwrap();
        assert!(
            matches!(envelope.body,AgentRequest::VmExec{command,..} if command==argv("exit 9"))
        );
        peer.write_all(
            &encode_message(&AgentResponse::Completed {
                exit_code: 9,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
    });
    let mut client = AgentClient::from_stream(client);
    assert!(run(
        &mut client,
        &["exit 9".into()],
        Context {
            image: None,
            image_info: None,
            env: &[],
            workdir: None,
            record_mounts: &[],
            overlay_id: "unused"
        },
        false
    )
    .unwrap_err()
    .to_string()
    .contains("init[0] failed (exit 9)"));
    server.join().unwrap();
}
