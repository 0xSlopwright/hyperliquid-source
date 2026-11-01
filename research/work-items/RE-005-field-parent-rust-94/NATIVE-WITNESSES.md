# Parent field-helper native witnesses

Read-only intake at #1030 head `5976ec53938ade09bdbb906e738b1abaab942d05`.
The original 390 bytes / 109 rows, full node #94 digest, six literals and raw
FDE/CIE bytes were independently rebound to one read-only admitted image.
All five flat and nine pretty published paths contain the actual ordered
common output witnesses. No new disassembler, callback, compiler, captured
program or target instruction interpreter was run.

These are conditional analytical transcripts for supplied normal callback
responses, not recorded target executions or a claim about the opaque value
callback's implementation.

Let S be entry state, E=byte(S+8), H=byte(S+9), and F the single pointer loaded
from S at `1571f8f`. H is restricted to 0/1 after E=0 for this proof's useful
prefix domain. Parent mode samples F+18 bit7 (bit23 of the full F+16 word).
The following MOVZX H does not change the mode TEST flags. H, mode and F's
reference are not resampled after callbacks.

## Raw-byte result table

| Stage | Response AL=00 | AL=02 | AL=80 | AL=ff |
| --- | --- | --- | --- | --- |
| Prior E!=0 (any prior H) | No callbacks; E=1 | Prior E=02 also E=1 | Prior E=80 also E=1 | Prior E=ff also E=1 |
| Flat prefix writer | Continue name | Stop E=1 | Stop E=1 | Stop E=1 |
| Flat name writer | Continue colon | Stop E=1 | Stop E=1 | Stop E=1 |
| Flat colon writer | Continue value G | Stop E=1 | Stop E=1 | Stop E=1 |
| Flat final G | Finish E=00 | **Finish E=02** | **Finish E=80** | **Finish E=ff** |
| Pretty H=0 opening | Snapshot current old-F words; continue | Stop E=1 | Stop E=1 | Stop E=1 |
| Pretty name/colon parent guard | Continue | Guard would stop E=1 | Guard would stop E=1 | Guard would stop E=1 |
| Pretty final G | Continue suffix | Stop E=1, no suffix | Stop E=1, no suffix | Stop E=1, no suffix |
| Pretty suffix, primitive parent call | Finish E=00 | Finish E=02 | Finish E=80 | Finish E=ff |

For the pretty name/colon and suffix calls, the preserved known-adapter bridge
restricts actual normal callee AL to 0/1. Underlying writer responses 02/80/ff
become adapter AL=1. Noncanonical suffix AL is a primitive parent relation,
not a reachable response claimed for that bridge; changing local L's target
would invalidate the bridge and is outside the proposed safe specialization.

Flat early errors use the initial R12b=1. Pretty opening restores the saved
name arguments then explicitly resets R12b=1 at `157203a`; normalization does
not assume any callback bool/Result representation. Pretty value errors also
use 1. Flat value and final suffix instead reach `MOV R12D,EAX` at `15720ce`
without a parent success/failure test, so their low byte propagates raw.

Every normal finish then performs, in native order:

1. `1571f6d`: store R12b into E.
2. `1571f71`: store H=1.
3. `1571f75`: set full RAX to original S.
4. `1571f86`: RET after the actual restoration sequence.

Parent RAX is **the original state pointer, not a returned status**. Callback
E/H writes are overwritten by these finish stores. Higher adapter result bits
and original Rust layouts are separate unknowns. A safe Rust logical return
of the same state reference must not be called an original pointer ABI or a
proof of physical generated-store order.

## Ordered requests and binding samples

Flat requests are `W(P(H)), W(name), W(": "), G(saved data, saved descriptor,F)`.
`P(0)` is `20 7b 20`; `P(1)` is `2c 20`. Even an empty flat name invokes W.
Before each of the first three writer calls, the native helper reads current
D=F+0 and V=F+8 from **cached old F**, then reads the current V+18 method entry.
Value G gets that old live F pointer; its descriptor pointer was saved before
callbacks but its +18 entry is loaded at the actual value call.

Pretty H=0 first directly requests `20 7b 0a` from old F's current D/V. H=1
skips that request. Then it initializes private N=1, copies old F's current
D/V into A, and samples the current full F+16 word into L. In H=0 these samples
are after opening. Parent mode still comes from the earlier sample even if
opening changed that word. The name and colon are requested through the known
adapter with A; G receives L and a real request capability may use shared N.
After G returns zero, the suffix reloads local L's data/descriptor and requests
`2c 0a`. Identifying that target with the adapter requires preserved A/L.

The adapter caches pointer values per invocation and reads a method entry anew
for every actual indentation/payload request. A stable closure does not by
itself prove a stable native writer function. The logical writer proxy must
represent those fresh selections or explicitly qualify the bridge.

## Critical mutable-state witnesses

- A successful flat prefix can write E=ff, H=80 and S.formatter=Fnew. There is
  no E/H recheck: name and colon still execute. They load fresh fields from
  **Fold**, not Fnew. Final E comes from G's raw AL and H becomes1.
- A flat callback may set Fold's bit23 after parent mode sampling. Parent
  remains flat, but G receives live Fold and can see its updated full flags.
  A flags accessor there must not substitute the old parent mode sample.
- Pretty H=0 opening can replace S.formatter and set Fold's D/V to Dp/Vp and
  its full flags to0. Parent remains pretty, yet A receives Dp/Vp and L sees
  flags0 from Fold. Re-fetching S.formatter or forcing the pretty flag back on
  would contradict the actual sample order.
- After pretty A/L sampling, changing Fold or S.formatter does not redirect
  local requests. Updating the captured V's method entry can affect later
  writer calls; changing L metadata would leave the known-adapter bridge.
- H=1 alone does not establish unchanged flags in arbitrary raw alias states.
  If F=A, the own `A+16=&N` store at `1572055` precedes `load F+16` at
  `1572059`. Thus even with no callback the later word can change. A safe
  logical model must separate F/A/L/frame or require equivalent noncorruption.
- A value callback may ignore an inner request failure and return00. Parent
  examines only G's returned AL; it then still attempts suffix. No implicit
  global sticky-error accumulator is justified.

Concrete conditional request example: H=1, empty name, all ordinary responses
zero except the G payload. Empty name causes no underlying W and leaves N=1
under the stated physical preservation conditions. Colon requests four spaces
then `: ` (pre-payload N=0). G requests `v\n`; its payload gets AL=80 after
N=1 was stored, so the adapter returns1. If G ignores that and returns00,
suffix still requests four spaces then `,\n`. If both succeed, parent finishes
E=0,H=1. This is a witness against replacing the supplied G response with an
accumulated hidden inner error, not a claim that the opaque native G does this.

## Feasibility and limits

GO for a chosen safe, reusable higher-order writer/context orchestration with
real byte-request capability, raw u8 callback results, mutable E/H/formatter
Cells, captured pointer identity and correct sample timing. It must retain
normal-return, saved-register/frame/control, immutable valid inputs, role
separation and preserved local metadata conditions. It does not implement the
opaque value formatter, private layout/ABI, physical rendering, arbitrary raw
alias states, faults/unwinding/concurrency or original runtime equivalence.
A fixed fake formatter, hardcoded value output or canonical Result assumption
would not establish this scope.
