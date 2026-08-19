//! `switchyardctl plugin test <command...>` — the Plugin Protocol v1
//! conformance runner (v0.4 cycle F). Plays the daemon's side of the
//! handshake against a plugin the author supplies as a shell command, and
//! reports pass/fail per check:
//!
//! 1. HELLO — first frame is `hello`, protocol_version 1, the name
//!    matches RELAYFABRIC_PLUGIN_NAME, capabilities present
//! 2. SEND — a routed `send` frame gets a `delivery_result` with the same
//!    corr (delivered may be false — the CONTRACT is that a result
//!    arrives; a sandboxed test has no live backend)
//! 3. SHUTDOWN — a `shutdown` frame makes the process exit 0
//!
//! Sync I/O on purpose: this is a CLI, and the frame format (4-byte
//! big-endian length + CBOR body) is trivially read with std. The frame
//! SHAPES come from serde_json values matched loosely, so this stays a
//! black-box protocol check, not a link against internal types.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 16 * 1024 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
const PLUGIN_NAME: &str = "conformance";

fn read_frame(stream: &mut UnixStream) -> Result<ciborium::Value, String> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("reading frame length: {e}"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(format!("frame of {len} B exceeds MAX_FRAME"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("reading frame body: {e}"))?;
    ciborium::from_reader(body.as_slice()).map_err(|e| format!("frame is not valid CBOR: {e}"))
}

fn write_frame(stream: &mut UnixStream, value: &ciborium::Value) -> Result<(), String> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|e| e.to_string())?;
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn text_field<'a>(map: &'a ciborium::Value, key: &str) -> Option<&'a str> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_text())
}

fn field<'a>(map: &'a ciborium::Value, key: &str) -> Option<&'a ciborium::Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn cbor_map(pairs: Vec<(&str, ciborium::Value)>) -> ciborium::Value {
    ciborium::Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (ciborium::Value::Text(k.into()), v))
            .collect(),
    )
}

struct Check(&'static str, Result<(), String>);

fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs the conformance ladder; returns process exit code (0 = all pass).
pub fn run(command: &str, config_json: &str, endpoint: &str) -> i32 {
    let dir = std::env::temp_dir().join(format!("rf-conformance-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock_path = dir.join("plugin.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind test socket: {e}");
            return 1;
        }
    };
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("RELAYFABRIC_SOCKET", &sock_path)
        .env("RELAYFABRIC_PLUGIN_NAME", PLUGIN_NAME)
        .env("RELAYFABRIC_PLUGIN_CONFIG", config_json)
        .env("PYTHONUNBUFFERED", "1")
        .stdin(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot spawn plugin command: {e}");
            return 1;
        }
    };

    // accept with timeout
    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    eprintln!("FAIL connect — plugin never connected within {STEP_TIMEOUT:?}");
                    kill(child);
                    return 1;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("accept failed: {e}");
                kill(child);
                return 1;
            }
        }
    };
    stream
        .set_read_timeout(Some(STEP_TIMEOUT))
        .expect("read timeout");

    let mut checks: Vec<Check> = Vec::new();

    // 1. HELLO
    let hello = read_frame(&mut stream);
    let hello_ok = hello.and_then(|h| {
        if text_field(&h, "t") != Some("hello") {
            return Err("first frame's t is not \"hello\"".into());
        }
        if text_field(&h, "plugin") != Some(PLUGIN_NAME) {
            return Err(format!(
                "hello.plugin is {:?}, expected RELAYFABRIC_PLUGIN_NAME ({PLUGIN_NAME:?})",
                text_field(&h, "plugin")
            ));
        }
        let pv = field(&h, "protocol_version")
            .and_then(|v| v.as_integer())
            .and_then(|i| i64::try_from(i).ok());
        if pv != Some(1) {
            return Err(format!("protocol_version is {pv:?}, expected 1"));
        }
        if field(&h, "capabilities").and_then(|c| c.as_map()).is_none() {
            return Err("hello.capabilities missing or not a map".into());
        }
        Ok(())
    });
    let hello_passed = hello_ok.is_ok();
    checks.push(Check("HELLO", hello_ok));

    if hello_passed {
        let ack = cbor_map(vec![
            ("t", "hello_ack".into()),
            ("protocol_version", 1.into()),
            ("error", ciborium::Value::Null),
        ]);
        if let Err(e) = write_frame(&mut stream, &ack) {
            checks.push(Check("SEND", Err(format!("cannot write hello_ack: {e}"))));
            report(&checks);
            kill(child);
            return 1;
        }

        // 2. SEND -> delivery_result. Other frame kinds (gauges, inbound)
        // may arrive interleaved; skip them.
        let send = cbor_map(vec![
            ("t", "send".into()),
            ("corr", "conformance-1".into()),
            ("endpoint", endpoint.into()),
            ("body", "conformance ping".into()),
        ]);
        let send_ok = write_frame(&mut stream, &send).and_then(|()| {
            let deadline = Instant::now() + STEP_TIMEOUT;
            loop {
                if Instant::now() > deadline {
                    return Err("no delivery_result before timeout".into());
                }
                let frame = read_frame(&mut stream)?;
                if text_field(&frame, "t") == Some("delivery_result") {
                    if text_field(&frame, "corr") == Some("conformance-1") {
                        return Ok(());
                    }
                    return Err(format!(
                        "delivery_result.corr is {:?}, expected \"conformance-1\"",
                        text_field(&frame, "corr")
                    ));
                }
                // gauges / inbound during the window are fine — skip.
            }
        });
        checks.push(Check("SEND", send_ok));

        // 3. SHUTDOWN -> exit 0
        let shutdown = cbor_map(vec![("t", "shutdown".into())]);
        let shutdown_ok = write_frame(&mut stream, &shutdown).and_then(|()| {
            let deadline = Instant::now() + STEP_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => return Ok(()),
                    Ok(Some(status)) => return Err(format!("exited {status}, expected 0")),
                    Ok(None) if Instant::now() > deadline => {
                        return Err("still running after shutdown frame".into());
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(e) => return Err(e.to_string()),
                }
            }
        });
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        checks.push(Check("SHUTDOWN", shutdown_ok));
        if !exited {
            kill(child);
        }
    } else {
        kill(child);
    }

    let _ = std::fs::remove_dir_all(&dir);
    report(&checks)
}

fn report(checks: &[Check]) -> i32 {
    let mut failed = false;
    for Check(name, result) in checks {
        match result {
            Ok(()) => println!("PASS {name}"),
            Err(e) => {
                failed = true;
                println!("FAIL {name} — {e}");
            }
        }
    }
    if failed {
        1
    } else {
        println!("conformant: Plugin Protocol v1");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_field_helpers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let frame = cbor_map(vec![("t", "hello".into()), ("protocol_version", 1.into())]);
        write_frame(&mut client, &frame).unwrap();
        let got = read_frame(&mut server).unwrap();
        assert_eq!(text_field(&got, "t"), Some("hello"));
        assert_eq!(
            field(&got, "protocol_version").and_then(|v| v.as_integer()),
            Some(1.into())
        );
    }

    #[test]
    fn oversize_frame_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client
            .write_all(&((MAX_FRAME as u32 + 1).to_be_bytes()))
            .unwrap();
        assert!(read_frame(&mut server).unwrap_err().contains("MAX_FRAME"));
    }
}
