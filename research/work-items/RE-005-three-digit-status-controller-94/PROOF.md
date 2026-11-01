# Exact selected relation and its stopping point

All coordinates below are linked node94 VAs. A common ET_DYN load biasD shifts both the RIP-derived table address and code addresses; adding each signed 32-bit table entry therefore selectsD+the recorded destination. It does not require assuming the file offset equals a VA.

## Selector

`0x1682237` reads the key length from the incoming RSI-record+16; `0x168223b/223e` excludes zero from the colon route. `0x1682244` reads the pointer from that record+8. The first physical byte comparison at `0x1682248` requires0x3a; mismatch branches to an unrelated route. Neither that unrelated route nor its helper outcomes is assigned a result here.

For an unsigned64-bit length L, the arithmetic at `0x1682251` yieldsI=(L-5) mod2^64 and`0x1682255/2259` branches away ifI>5. If0<=L<5, the wrapped result is at least 2^64-5>5; ifL>=5, I=L-5 without wrapping. Thus admitted I=0..5 corresponds exactly to L=5..10. The table read at `0x1682266` sign-extends a DWORD at base+4I; the next ADD/JMP uses the same base. The 24 actual bytes are:

```text
a7274001 ae2b4001 64294001 ae2b4001 d1284001 e6294001
```

| I | L | Signed entry | Destination |
| --- | --- | --- | --- |
| 0 | 5 | 20981671 | `0x168226f` |
| 1 | 6 | 20982702 | `0x1682676` |
| 2 | 7 | 20982116 | `0x168242c` |
| 3 | 8 | 20982702 | `0x1682676` |
| 4 | 9 | 20981969 | `0x1682399` |
| 5 | 10 | 20982246 | `0x16824ae` |

The actual table is in the unique file-backed .rodata mapping at file offset 2620104; it is not executable code. The two exact selected FDE/CIE records bind caller`[0x1682220,0x1682735)` and existing leaf`[0x1683670,0x16836c5)`. This is narrow record/known-encoding qualification, not a new unwind census or complete exception proof.

The L=7 target loads byte1 at `0x168242c`, compares it to0x73 at `0x1682430` and takes JE `0x1682433` to `0x16825cc`. There, the byte2 load is compared first against 0x63 (alternate route), then against 0x74 (selected route). The byte3/4/5/6 comparisons at `0x16825de/25e8/25f2/25f8` require 0x61/0x74/0x75/0x73. No key-pointer register is replaced before these comparisons finish. Together with the colon/length conditions, they are exactly key7=`:status`.

The retained 318 raw instruction records concatenate to the exact1,301-byte body and have contiguous physical instruction starts. The static test graph derives rel8/rel32 destinations from their encoded fields and uses only the real six-entry table for the indirect JMP. Removing each of the eleven selected necessary edges makes CALL `0x1682606` unreachable from the ordinary caller entry. There is no earlier helper on the selected prefix. The graph treats ordinary calls elsewhere as fallthrough only under an explicit normal-call assumption; it does not execute registers, flags, memory or target instructions, or prove exceptions/external-entry behavior. The selected raw operand and edge bindings, exact complete-body hash, table and retained native evidence must all agree.

## Leaf and writes

The selected caller loads RDI=`[R15+8]` at `0x16825fe` and RSI=`[R15+16]` at `0x1682602`. The actual CALL rel32 at `0x1682606` resolves to `0x1683670`. The existing 85-byte parser has no helper calls or explicit stores: length!=3 returns0 before reading value bytes; length 3 reads the three bytes and returns0 unless the first is ASCII1..9 and the others0..9. Its bounded arithmetic gives 100d0+10d1+d2 in 100..999. This previously established behavior is a dependency, not new recovered-source credit.

The actual16-bit AX test at `0x168260b` controls JE `0x168260e` to `0x16822fd`. On the nonzero edge, `66 41 89 06` at `0x1682614` is a WORD store through R14, followed by `41 c6 46 40 07` at `0x1682618`, a BYTE store of 7 at offset 64. On the zero edge, `41 c6 06 07` at `0x16822fd` is a BYTE store of 7 at offset0, followed by `41 c6 46 40 08` at `0x1682301`, a BYTE store of 8 at offset 64. The distinction is material: invalid output byte 1 is not written in this stage. Store ordering is physical instruction order, and byte ordering of the WORD is x86 little-endian.

The observation ends immediately after these two stores. It uses valid memory at the actual read/write widths, protected code/return/frame state, ordinary entry/control and no concurrent mutation. Requiring nonaliasing/separation from records/key/value/frame/code is an explicit domain condition, not an inferred Rust lifetime or owned-string layout.

## Why final returned contents remain unknown

The nonzero route jumps to `0x168267f`, then loads the value-record first QWORD, its +8/+16 fields, advances the record address by 24 and calls the target at `[first_QWORD+32]` at `0x1682691`. The invalid route does the analogous setup at `0x1682306` and callback at `0x1682318`. Both later reach the key-record callback at `0x16826a3`. After those calls, the bytes at `0x16826a6` copy the then-current R14 register to RAX and encode an epilogue ending at RET `0x16826b7`. Preservation of R14's original output-address role through either callback also requires an unobserved register/frame contract.

No target from either runtime table is bound in this contribution. Calling those effects a destructor/free/no-op or assuming they cannot alias/change the output would invent the missing evidence. Normal completion, unwinding, final memory and other key routes stay unqualified. There is no staged Rust API, whole-return controller, byte-equivalent code, full-node claim, or gate change.
