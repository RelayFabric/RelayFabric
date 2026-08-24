# Plugin Protocol v1: Golden Wire Vectors

Language-neutral, byte-exact vectors for the CBOR-over-Unix-socket plugin
IPC (v0.4 cycle F). A new-language implementation is conformant when it
reproduces these frames byte-for-byte AND passes
`switchyardctl plugin test "<your plugin command>"`.

Frame format: 4-byte big-endian body length, then a CBOR map whose `t` key
names the frame. **Key order matters**: CBOR maps encode in declaration
order and these bytes are locked; both reference implementations
(`crates/relay-ipc`, `sdk/python/relayfabric_sdk/ipc.py`) assert them in
their test suites.

## Vector 1: `hello`

`Hello { plugin: "lxmf", version: "0.1.0", protocol_version: 1, capabilities:
{ text: true, direct_messages: true, groups: true, attachments: false,
location: false, reactions: false, receipts: false, presence: false,
max_payload: null } }`

```text
000000a5a561746568656c6c6f66706c7567696e646c786d666776657273696f6e65302e31
2e307070726f746f636f6c5f76657273696f6e016c6361706162696c6974696573a9647465
7874f56f6469726563745f6d65737361676573f56667726f757073f56b6174746163686d65
6e7473f4686c6f636174696f6ef4697265616374696f6e73f4687265636569707473f46870
726573656e6365f46b6d61785f7061796c6f6164f6
```

## Vector 2: `inbound` with one attachment

`Inbound { endpoint: "chan", sender: "s", kind: "text", body: "hi",
created_at: null, attachments: [{ filename: "a.bin", mime:
"application/octet-stream", data: 0x010203 }], priority: null }`

```text
0000008fa8617467696e626f756e6468656e64706f696e74646368616e6673656e64657261
73646b696e64647465787464626f64796268696a637265617465645f6174f66b6174746163
686d656e747381a36866696c656e616d6565612e62696e646d696d6578186170706c696361
74696f6e2f6f637465742d73747265616d646461746143010203687072696f72697479f6
```

Sources of truth (assert these in the same bytes):

- Rust: `crates/relay-ipc/src/lib.rs` (`canonical_hello_frame_bytes_are_stable`,
  `canonical_inbound_attachment_frame_bytes_are_stable`)
- Python: `sdk/python/tests/test_ipc.py` (`CANONICAL_HELLO_HEX`,
  `CANONICAL_INBOUND_ATTACHMENT_HEX`)
