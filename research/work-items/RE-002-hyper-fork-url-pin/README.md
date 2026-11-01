# RE-002: what the hyper-fork adds to HttpConnector

- Component ID: build provenance / patched forks (RE-002); network client path (RE-012 adjacent)
- Target release and full SHA-256:
  - node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (all anchors)
  - node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (strings and fork-only Location points)
- Source commit: repository `main` at `cec50f68`. Upstream reference: hyper `v0.14.16` (`41dee4a7`), `src/client/connect/http.rs`.
- Claim status: observation for every anchor, inference for the reconstructed Rust shape. No implementation and no gate.
- Scope included: the fork-only code in `hyper-fork/src/client/connect/http.rs`, i.e. Location points 494:21, 515:28, 546:55 and 558:85, which have no upstream counterpart at any line shift.
- Scope excluded: the public setter that fills the new map (in the +10-line hunk before upstream L270), the first-party code that calls it, and the other patched hyper files.

## Question and answer

The hyper-fork base is hyper 0.14.16. Its `connect/http.rs` is 42 lines longer, and four panic Locations fall in lines that upstream does not have. What do those lines do?

**They add a URL-to-address pin.** `HttpConnector`'s `Config` gets a `BTreeMap<String, SocketAddr>`. For each connection, the destination URI string is tested against every key with `str::contains`:

- If exactly one key matches, the connector prints `hyper-fork only trying <addr> on <uri>` to stdout and connects only to that `SocketAddr`. The DNS results are ignored.
- If two keys match, it panics with `two matching urls <key1> <key2>`.
- If no key matches, it behaves like upstream.

Reconstructed shape (inference, written from the bytes, not copied source):

```rust
// ConnectingTcp::new(dst: String, remote_addrs, config)   fork L~476..503
let mut pin: Option<SocketAddr> = None;
let mut matched: Option<&String> = None;
if config.<flag at +0x20> == 1 && !config.<map>.is_empty() {
    for (key, addr) in &config.<map> {               // BTreeMap<String, SocketAddr>
        if dst.contains(key.as_str()) {
            if let Some(prev) = matched { panic!("two matching urls {} {}", prev, key); }   // L494:21
            matched = Some(key);
            pin = Some(*addr);
        }
    }
}
// ... ConnectingTcpRemote::new(dst.clone(), addrs, timeout, pin)   L515:28 is the fallback sleep
// ConnectingTcpRemote::connect                                     L558:85 is this async fn
let addrs: Vec<SocketAddr> = match self.pin {
    Some(a) => { println!("hyper-fork only trying {} on {}", a, self.dst); vec![a] }
    None => self.addrs.by_ref().collect(),
};
```

## Reproduce

```sh
python3 tools/hyper_fork_url_pin.py --check            # all anchors, both captures
python3 -m unittest discover -s tests -p test_hyper_fork_url_pin.py   # 6 tests incl. corruption controls
```

Python 3.12.3. GNU objdump 2.42 was used for reading only; the tool decodes the RIP-relative operands itself. `hyper-fork-url-pin.json` SHA-256: `6de57d85af1b914cf7d99f871b9138b32a7d85848967c6c2ac0508779f7f3809`, byte-identical under `PYTHONHASHSEED=7`. Captured binaries were not executed.

## Evidence (node #94 virtual addresses)

Function ranges come from `make index` (`work/index/node-94-unwind.tsv`):

| Function | Range | Identified by |
| --- | --- | --- |
| `ConnectingTcp::new` (fork) | `0x29c1930..0x29c2e40` | Locations 494:21 and 515:28 |
| `ConnectingTcpRemote::new` (fork) | `0x29c3190..0x29c3300` | Location 546:55 and `divide by zero error when dividing duration by scalar` (upstream L518:55 `t / (addrs.len() as u32)`) |
| `ConnectingTcpRemote::connect` poll | `0x22b64a0..0x22b75b0` | Location 558:85, one of six instances (four in #115) |
| `HttpConnector::call_async` poll | `0x2428800..0x242b110` | calls `ConnectingTcp::new` through GOT `0x576f078`, one of three callers |
| `tokio::time::sleep` | `0x4f65d40..0x4f65ee0` | references `A Tokio 1.x context was found, but timers are disabled` |
| `std::io::_print` | `0x4edba50..0x4edbb20` | references `stdout` |
| `<http::Uri as Display>::fmt` | `0x299efd0..0x299f1c0` | references `/*` and `http` `path.rs` Locations |

Key anchors (the tool checks all 30 for exact bytes and resolved targets):

| VA | Instruction | Meaning |
| --- | --- | --- |
| `0x2428ee5` | `call *GOT→0x299efd0` | `dst.to_string()`: the URI is formatted into a new `String` |
| `0x2428f6d` | `call *GOT→0x29c1930` | `ConnectingTcp::new(&dst_string, addrs, config)` |
| `0x29c1962` | `movw $0x2,0x1b0(%rsp)` | `pin = None` (tag 2 is the `Option<SocketAddr>` niche) |
| `0x29c1971` | `cmpl $0x1,0x20(%rcx)` | map is used only when `Config+0x20 == 1`; root at +0x28, length at +0x38 |
| `0x29c1a32` | `movzwl 0x272(%r13),%ecx` | B-tree leaf `len` at +0x272 |
| `0x29c1bf8`, `0x29c1c09` | `mov 0x178/0x170(%rbp,%rax,8)` | `keys[i]` = `String {cap,ptr,len}` at +0x168+24·i |
| `0x29c2686`..`0x29c26a4` | `shl $5` / `movdqu` / `movdqa → 0x1b0` | `pin = Some(vals[i])`, 32-byte values at +0 |
| `0x29c267a`, `0x29c2680` | `cmpq $0,0x20(%rsp)` / `jne 0x29c2c21` | second match goes to the panic block |
| `0x29c2c7b`, `0x29c2c82`, `0x29c2c8e` | template `0x1fd505`, Location 494:21, `call *GOT→0x157b810` | `panic!("two matching urls {} {}")` |
| `0x29c2a17`, `0x29c2a2a` | Location 515:28, `call *GOT→0x4f65d40` | `tokio::time::sleep(fallback_timeout)` (upstream L491, 4 columns deeper) |
| `0x29c325c`..`0x29c326b` | stores to `+0x48`, `+0x18`, `+0x20`, `+0x28` | `ConnectingTcpRemote { dst: String @0, connect_timeout @0x18, pin @0x28, addrs @0x48 }` |
| `0x22b64fb`, `0x22b6502` | `cmpw $0x2,0x28(%r12)` / `jne` | `match self.pin` |
| `0x22b663f`, `0x22b664e` | template `0x2005d4`, `call *GOT→0x4edba50` | `println!("hyper-fork only trying {} on {}")` |
| `0x22b6654` | `mov $0x20,%edi` then alloc | `vec![pin]`: one 32-byte `SocketAddr` |

Further observations:

- **Leaf layout.** The 626-byte leaf (`len` at +0x272) is `vals[11]` (11·32 = 0x160), `parent` (+0x160), `keys[11]` (+0x168, 11·24), `parent_idx` (+0x270), `len` (+0x272). So K = `String` and V = 32 bytes, which is the size of `std::net::SocketAddr`. `connect` stores it in an `Option` with niche tag 2 and later reads its tag as V4/V6.
- **Search direction.** An empty key matches at once. A key at least as long as the URI is compared with `bcmp`. Otherwise the core `&str` two-way searcher runs with the URI as haystack (`pattern.rs:1128/1496/1508/1809` Locations, rustc `e408947`). That is `dst.contains(key)`.
- **No bind change.** The socket helper `0x29c3300` keeps upstream `bind_local_address` behavior: two `bind` calls fed only from `config.local_address_ipv4/ipv6` (tags at +0x71/+0x76).

Node #115 has the same two templates (file offsets `0x44be0e`, `0x44e4d0`) and the same fork-only `z_forks/hyper-fork/src/client/connect/http.rs` points. Each point is referenced from `.text`: 494:21, 515:28 and 546:55 once each, and 558:85 from four `connect` instances.

## Implementation and comparison

Not implemented. The Rust above is a description of the observed behavior, not a reconstruction claim.

## Results and limitations

- Observation: 30 #94 anchors (bytes plus resolved targets), 3 helper identifications by string reference, and the #115 strings and Location references.
- Inference: the Rust shape, the field names (`pin`, `dst`), and `SocketAddr` as the value type (from size, niche and V4/V6 tag use).
- Not determined: the setter name and signature, the meaning of `Config+0x20 == 1` (a flag or enum tag in front of the map), the first-party callers that fill the map, and its runtime contents. No captured binary was run, so no URL or address values are known.
- Behavior notes for reviewers: a pinned destination ignores the DNS results. All four `ConnectingTcpRemote::new` calls (`0x29c2722`, `0x29c28db`, `0x29c2a12`, `0x29c2a87`), including the Happy Eyeballs fallback ones, receive the same pin slot (`r9 = 0x1b0(%rsp)`). An ambiguous configuration panics the connecting task.
- No progress gate is requested.

Next question: which first-party function fills `Config+0x20..+0x38` (the setter in the +10-line hunk before upstream L270), and with which key/address pairs?
