//! A local RPC endpoint replaying the recorded testnet target capture, shared by the CLI and MCP
//! boundary tests of `capture-target`.
//!
//! The replies are the verbatim `result` objects in
//! `crates/source-rpc/tests/captured-testnet/target-capture-protocol30/`, the same ones the source-rpc
//! conformance test replays in process. Here they travel over HTTP, so each shell's operator
//! source configuration, transport and output path are the ones a real capture uses. Nothing
//! reaches a network.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use stellar_xdr::{
    HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, ReadXdr, ScAddress, ScVal, SequenceNumber,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

pub const NETWORK: &str = "Test SDF Network ; September 2015";

/// The recorded `result` for one RPC method.
pub fn recorded(method: &str) -> Value {
    let text = match method {
        "getNetwork" => include_str!(
            "../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/getNetwork.json"
        ),
        "simulateTransaction" => include_str!(
            "../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/simulateTransaction.json"
        ),
        "getLedgerEntries" => include_str!(
            "../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/getLedgerEntries.json"
        ),
        "getLedgers" => include_str!(
            "../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/getLedgers.json"
        ),
        other => panic!("no recorded reply for {other}"),
    };
    serde_json::from_str(text).expect("recorded reply JSON")
}

/// The recorded transfer call: the root of the authorization the recorded record-mode
/// simulation returned, which capture requires to equal the envelope's call exactly.
pub fn recorded_call() -> InvokeContractArgs {
    let auth = recorded("simulateTransaction")["results"][0]["auth"][0]
        .as_str()
        .expect("recorded authorization")
        .to_string();
    let entry = SorobanAuthorizationEntry::from_xdr_base64(auth, Limits::none())
        .expect("recorded authorization XDR");
    match entry.root_invocation.function {
        SorobanAuthorizedFunction::ContractFn(call) => call,
        _ => panic!("the recorded root is a contract call"),
    }
}

/// The unsigned envelope the recorded responses answer: the recorded call, with its recipient
/// as the simulation source account, exactly as the source-rpc conformance test builds it.
pub fn envelope() -> String {
    envelope_with(|_| {})
}

/// [`envelope`] with its call changed by `mutate`.
pub fn envelope_with(mutate: impl FnOnce(&mut InvokeContractArgs)) -> String {
    let mut call = recorded_call();
    let ScVal::Address(ScAddress::Account(recipient)) = &call.args[1] else {
        panic!("the recorded call pays a G account");
    };
    let stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(recipient)) = recipient.0.clone();
    mutate(&mut call);
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            // Simulation needs an existing source account; it is never charged or signed.
            source_account: MuxedAccount::Ed25519(Uint256(recipient)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(call),
                    auth: Default::default(),
                }),
            }]
            .try_into()
            .expect("one operation"),
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .expect("envelope XDR")
}

/// The operator source map naming `url` as `testnet`.
pub fn sources(url: &str) -> String {
    json!({"testnet": {"rpc_url": url, "network_passphrase": NETWORK}}).to_string()
}

/// A JSON-RPC reply: `Ok(result)` or `Err(error object)`, or a raw HTTP response.
pub enum Reply {
    Result(Value),
    Error(Value),
    /// Status and body sent as they are, for a proxy or gateway that is not JSON-RPC.
    Http(u16, String),
}

type Responder = dyn Fn(&str, usize) -> Reply + Send + Sync;

/// A local endpoint answering every request through `responder(method, nth call of that
/// method)`, recording each request, until [`ReplayEndpoint::finish`].
pub struct ReplayEndpoint {
    pub url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ReplayEndpoint {
    /// Replays the recorded responses.
    pub fn recorded() -> Self {
        Self::bind(|method, _| Reply::Result(recorded(method)))
    }

    pub fn bind(responder: impl Fn(&str, usize) -> Reply + Send + Sync + 'static) -> Self {
        let responder: Arc<Responder> = Arc::new(responder);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = thread::spawn({
            let (requests, stop) = (requests.clone(), stop.clone());
            move || loop {
                match listener.accept() {
                    Ok((stream, _)) => answer(stream, &responder, &requests),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept on replay endpoint: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// Stop listening and return every request received, in order.
    pub fn finish(mut self) -> Vec<Value> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("replay endpoint thread");
        }
        let requests = self.requests.lock().unwrap();
        requests.clone()
    }
}

/// The methods of `requests`, in order.
pub fn methods(requests: &[Value]) -> Vec<String> {
    requests
        .iter()
        .map(|request| request["method"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn answer(mut stream: TcpStream, responder: &Arc<Responder>, requests: &Mutex<Vec<Value>>) {
    // A socket accepted from a non-blocking listener is itself non-blocking on BSD and macOS.
    stream.set_nonblocking(false).expect("blocking RPC stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = read_request(&mut stream);
    let method = request["method"].as_str().expect("RPC method").to_string();
    let nth = {
        let mut requests = requests.lock().unwrap();
        let nth = requests
            .iter()
            .filter(|seen| seen["method"] == method.as_str())
            .count();
        requests.push(request.clone());
        nth
    };
    let (status, body) = match responder(&method, nth) {
        Reply::Result(result) => (
            200,
            json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string(),
        ),
        Reply::Error(error) => (
            200,
            json!({"jsonrpc": "2.0", "id": request["id"], "error": error}).to_string(),
        ),
        Reply::Http(status, body) => (status, body),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn read_request(stream: &mut TcpStream) -> Value {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("HTTP request header");
        header.push(byte[0]);
        assert!(header.len() <= 16_384, "oversized HTTP header");
    }
    let header = String::from_utf8(header).expect("ASCII HTTP header");
    let length: usize = header
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(key, value)| {
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().expect("content length"))
            })
        })
        .expect("content length");
    assert!(length <= 1_048_576, "oversized RPC request");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("HTTP request body");
    serde_json::from_slice(&body).expect("RPC request JSON")
}
