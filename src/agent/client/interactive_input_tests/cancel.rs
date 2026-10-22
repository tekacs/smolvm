use super::*;

#[test]
fn explicit_cancel_retains_reads_until_exit_is_acknowledged() {
    let (client_stream, mut guest_stream) = UdsStream::pair().unwrap();
    let (input, receiver) = interactive_input(2).unwrap();
    let (closed_tx, closed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (request_tx, request_rx) = mpsc::channel();
    let (admit_tx, admit_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let guest = std::thread::spawn(move || {
        let mut header = [0u8; 4];
        guest_stream.read_exact(&mut header).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(header) as usize];
        guest_stream.read_exact(&mut payload).unwrap();
        request_tx.send(()).unwrap();
        admit_rx.recv_timeout(DEADLINE).unwrap();
        guest_stream
            .write_all(&smolvm_protocol::encode_message(&AgentResponse::Started).unwrap())
            .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            guest_stream.read(&mut byte).unwrap(),
            0,
            "only writes are closed"
        );
        closed_tx.send(()).unwrap();
        release_rx.recv_timeout(DEADLINE).unwrap();
        guest_stream
            .write_all(
                &smolvm_protocol::encode_message(&AgentResponse::Exited {
                    exit_code: 137,
                    oom: false,
                })
                .unwrap(),
            )
            .unwrap();
    });
    let session = std::thread::spawn(move || {
        AgentClient::from_stream(client_stream).interactive_session_io(
            request(&["cat"]),
            receiver.require_exit(),
            move |event| {
                if event == InteractiveOutput::Started {
                    started_tx.send(()).unwrap();
                }
            },
            "cancel test",
            NEVER_MS,
        )
    });
    request_rx.recv_timeout(DEADLINE).unwrap();
    assert!(
        matches!(started_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "host allocation is not Started"
    );
    admit_tx.send(()).unwrap();
    started_rx.recv_timeout(DEADLINE).unwrap();
    runtime()
        .block_on(input.send(InteractiveInput::Cancel))
        .unwrap();
    closed_rx.recv_timeout(DEADLINE).unwrap();
    assert!(
        !session.is_finished(),
        "a half-close is not an exit receipt"
    );
    release_tx.send(()).unwrap();
    assert_eq!(session.join().unwrap().unwrap(), 137);
    guest.join().unwrap();
}

#[test]
fn custody_reports_channel_loss_as_unknown_instead_of_a_numeric_exit() {
    let (client_stream, guest_stream) = UdsStream::pair().unwrap();
    let guest = FakeGuest::spawn(guest_stream);
    let (input, receiver) = interactive_input(2).unwrap();
    let session = std::thread::spawn(move || {
        AgentClient::from_stream(client_stream).interactive_session_io(
            request(&["cat"]),
            receiver.require_exit(),
            |_| {},
            "custody test",
            NEVER_MS,
        )
    });
    drop(input);
    assert!(session.join().unwrap().is_err());
    guest.finish();
}

#[test]
fn cancel_kills_the_owned_process_instead_of_returning_on_channel_loss() {
    let (input, _output, session, guest) = session(&["cat"], 2);
    runtime()
        .block_on(input.send(InteractiveInput::Cancel))
        .unwrap();
    assert_ne!(session.join().unwrap().unwrap(), DISCONNECT_EXIT_CODE);
    guest.finish();
}
