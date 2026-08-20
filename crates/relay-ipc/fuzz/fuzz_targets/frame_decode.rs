//! Fuzz the Plugin Protocol v1 frame bodies: arbitrary bytes must never
//! panic the CBOR decode of either direction's enum, and anything that
//! DOES decode must re-encode without panicking (the codec is the trust
//! boundary between the daemon and every plugin).
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_ipc::{DaemonToPlugin, PluginToDaemon};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = ciborium::from_reader::<PluginToDaemon, _>(data) {
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&frame, &mut buf);
    }
    if let Ok(frame) = ciborium::from_reader::<DaemonToPlugin, _>(data) {
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&frame, &mut buf);
    }
});
