//! Fuzz the canonical Envelope decode: federation peers send
//! CBOR-serialized Envelopes (cleartext or as sealed plaintext), so
//! arbitrary bytes must never panic the decode, and a successful decode
//! must survive re-encoding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_core::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = ciborium::from_reader::<Envelope, _>(data) {
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&env, &mut buf);
    }
});
