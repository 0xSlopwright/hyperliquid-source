# RE-010 — execute-action dispatch tags → handler functions (node #94)

Target: `artifacts/node/94/hl-node`, sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Claims checked: `references/can1357-hl/l1/exchange/impl_execute_action.rs` (submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`), its 76 `HandlerRef::new` entries.

Tool: `tools/exchange_dispatch.py` (stdlib only). Tests: `tests/test_exchange_dispatch.py`.
All addresses are virtual addresses of instruction starts, REX prefix included.

## Method

1. **Dispatcher bounds** come from `.eh_frame_hdr`. The FDE runs from `0x2759240` to `0x275a376` (end exclusive). The binary has 121299 FDEs, the same count `readelf -wf` gives.
2. **Tag bias.** The tool expects these exact bytes at `0x2759298`: `mov rax,[r12]; lea rcx,[rax-0x74]; cmp rax,0x74; mov eax,0x14; cmovae rax,rcx`. So the table index is `tag-0x74`, and any discriminant below `0x74` goes to index 20.
3. **Jump table.** `lea rcx,[rip+…]` at `0x27592ad` points to the table at `0x3ede28`. The jump is `movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax`, with no bounds check. The tool reads entries until a target falls outside the dispatcher FDE. That gives 88 entries, all with distinct targets.
4. **Arm path.** From each arm, the tool decodes instructions in a straight line with a strict subset decoder. Any opcode outside the subset raises an error; the decoder never guesses. It stops at the first `call` or `jmp`.
   - A rel32 call target has to be an FDE start.
   - A `call [rip+x]` slot has to carry an `R_X86_64_RELATIVE` relocation, and the tool uses its addend as the target.
   - Each conditional branch on the path is followed one level, to its own first call or jmp.
5. **Classification** of each `HandlerRef` claim:
   - `real_first_call`: the claimed address is an FDE start, and it is the first call on the arm's straight-line path.
   - `real_first_call_on_branch`: the main path makes no call, and the claimed function is the first call reached through a conditional branch on the arm.
   - `inline_claim_no_call`: the claim names the dispatcher itself, and the arm makes no call.
   - `claimed_not_fde_start` / `fde_start_not_called_from_arm`: the claim failed. No claim in this reconstruction lands here; only the tamper tests reach these.
6. **Address survey.** Every hex literal in `l1/exchange/**/*.rs` that falls in the `.text` range is checked against FDE bounds.
7. **Panic Locations.** The binary contains no `impl_execute_action.rs` string, so for this file no handler is pinned by a panic Location. Nothing here relies on one.

## Findings

- **74 of the 76 claimed handlers are real functions**, and each one is the first call on its arm (status `real_first_call`). Three of those first calls go through relocated slots:
  - case 16: `0x5773160` → `0x3367800`;
  - case 40: `0x57731b0` → `0x374ec60`;
  - case 63's branch: `0x5773130` → `0x3996230`.
- **Case 63 (`cUserModify`, claimed `0x3996230`) is real but conditional.** The handler runs only when `byte [r15+0x8f2] != 3` (`jne` at `0x2759a83` → `0x275a318`, then the slot call at `0x275a342`). Otherwise the arm writes `0x8d` to `[rsp+0x70]` and jumps to `0x275a180` without calling anything.
- **Case 0 (`noop`) has no handler.** Its arm at `0x2759452` writes `0xd` to `[rsp+0x68]` and jumps to `0x275a186`. The reconstruction's `0x2759240` is the dispatcher itself, so this one is an inline no-op and not a separate function.
- **Agent-invented splits.** The binary has no function boundary at these three addresses from the exchange tree; each sits inside a larger FDE:
  - `handlers/01_approve_agent3.rs` cites `0x1bf18b0` as the root of a JSON serializer. It is inside FDE `0x1befd10..0x1bf4616`.
  - `handlers/05_claim_rewards.rs` cites `0x2759c55` and `0x2759c9e`. Both are inside the dispatcher FDE. `0x2759c55` is the case-5 arm, a 4-instruction wrapper that calls `0x2710e30`. The real function is `0x2710e30`, which is what the HandlerRef claims.
  - The other 206 `.text`-range literals in the tree sit exactly at FDE starts.
- **12 table entries have no claim (cases 76..87, tags 192..203).** Their first calls are recorded in the JSON. They are not named here.
- **Conditional branches before the first call** are found at four places, and they match objdump exactly:
  - case 61 at `0x2759bcf`;
  - case 63 at `0x2759a83`;
  - case 66 at `0x275942d`;
  - case 76 at `0x2759b68`.

## Tag table

| idx | tag | wire type | Rust variant | arm | claimed | first call | status |
|---|---|---|---|---|---|---|---|
| 0 | 116 | noop | NoopAction | 0x2759452 | 0x2759240 | - | inline_claim_no_call |
| 1 | 117 | approveAgent | ApproveAgent3Action | 0x27592bd | 0x1e5f770 | 0x1e5f770 | real_first_call |
| 2 | 118 | batchModify | BatchModifyAction | 0x2759a0e | 0x21dfd90 | 0x21dfd90 | real_first_call |
| 3 | 119 | cancel | CancelAction | 0x2759a95 | 0x22be610 | 0x22be610 | real_first_call |
| 4 | 120 | cancelByCloid | CancelByCloidAction | 0x27598ae | 0x21dff60 | 0x21dff60 | real_first_call |
| 5 | 121 | claimRewards | ClaimRewardsAction | 0x2759c55 | 0x2710e30 | 0x2710e30 | real_first_call |
| 6 | 122 | createSubAccount | CreateSubAccountAction | 0x2759d2a | 0x27e3140 | 0x27e3140 | real_first_call |
| 7 | 123 | createVault | CreateVaultAction | 0x2759ac2 | 0x1e5f3c0 | 0x1e5f3c0 | real_first_call |
| 8 | 124 | evmRawTx | EvmRawTxAction | 0x2759da0 | 0x1f661c0 | 0x1f661c0 | real_first_call |
| 9 | 125 | ForceIncreaseEpoch | ForceIncreaseEpochAction | 0x2759998 | 0x21e0a00 | 0x21e0a00 | real_first_call |
| 10 | 126 | liquidate | LiquidateAction | 0x2759d84 | 0x23e66f0 | 0x23e66f0 | real_first_call |
| 11 | 127 | linkStakingUser | LinkStakingUserAction | 0x2759849 | 0x1e60770 | 0x1e60770 | real_first_call |
| 12 | 128 | modify | ModifyAction | 0x275996b | 0x22be760 | 0x22be760 | real_first_call |
| 13 | 129 | NetChildVaultPositions | NetChildVaultPositionsAction | 0x2759cfd | 0x27e8cb0 | 0x27e8cb0 | real_first_call |
| 14 | 130 | order | OrderAction | 0x275977e | 0x1eee7c0 | 0x1eee7c0 | real_first_call |
| 15 | 131 | registerReferrer | RegisterReferrerAction | 0x2759a3b | 0x27e30a0 | 0x27e30a0 | real_first_call |
| 16 | 132 | registerValidator | RegisterValidatorAction | 0x27596fd | 0x3367800 | 0x3367800 | real_first_call |
| 17 | 133 | CValidator | CValidatorAction | 0x2759b0b | 0x2768ff0 | 0x2768ff0 | real_first_call |
| 18 | 134 | scheduleCancel | ScheduleCancelAction | 0x2759d57 | 0x1e5fc40 | 0x1e5fc40 | real_first_call |
| 19 | 135 | setDisplayName | SetDisplayNameAction | 0x2759ee6 | 0x27e2170 | 0x27e2170 | real_first_call |
| 20 | 136 | VoteGlobal | VoteGlobalAction | 0x2759b94 | 0x23e8640 | 0x23e8640 | real_first_call |
| 21 | 137 | ValidatorL1Vote | ValidatorL1VoteAction | 0x2759cd0 | 0x22cdb40 | 0x22cdb40 | real_first_call |
| 22 | 138 | ValidatorL1Stream | ValidatorL1StreamAction | 0x2759e81 | 0x21e0370 | 0x21e0370 | real_first_call |
| 23 | 139 | validatorL1UpdateReferenceOracle | ValidatorL1UpdateReferenceOracleAction | 0x2759f78 | 0x27fa570 | 0x27fa570 | real_first_call |
| 24 | 140 | setGlobal | SetGlobalAction | 0x27599e1 | 0x1f67b30 | 0x1f67b30 | real_first_call |
| 25 | 141 | setReferrer | SetReferrerAction | 0x27599b4 | 0x27de270 | 0x27de270 | real_first_call |
| 26 | 142 | spotDeploy | SpotDeployAction | 0x275a01b | 0x23e7d10 | 0x23e7d10 | real_first_call |
| 27 | 143 | spotUser | SpotUserAction | 0x27596b4 | 0x21cfec0 | 0x21cfec0 | real_first_call |
| 28 | 144 | spotSend | SpotSendAction | 0x2759fa5 | 0x1f66070 | 0x1f66070 | real_first_call |
| 29 | 145 | SignValidatorSetUpdate | SignValidatorSetUpdateAction | 0x2759fd2 | 0x1e642e0 | 0x1e642e0 | real_first_call |
| 30 | 146 | subAccountModify | SubAccountModifyAction | 0x2759dcd | 0x22cdfb0 | 0x22cdfb0 | real_first_call |
| 31 | 147 | subAccountTransfer | SubAccountTransferAction | 0x2759aef | 0x1e60d00 | 0x1e60d00 | real_first_call |
| 32 | 148 | subAccountSpotTransfer | SubAccountSpotTransferAction | 0x2759dfa | 0x1e64420 | 0x1e64420 | real_first_call |
| 33 | 149 | tokenDelegate | TokenDelegateAction | 0x27597ab | 0x1e5fa70 | 0x1e5fa70 | real_first_call |
| 34 | 150 | twapCancel | TwapCancelAction | 0x27596d0 | 0x22c4630 | 0x22c4630 | real_first_call |
| 35 | 151 | twapOrder | TwapOrderAction | 0x2759588 | 0x2722790 | 0x2722790 | real_first_call |
| 36 | 152 | updateIsolatedMargin | UpdateIsolatedMarginAction | 0x275966b | 0x21e2b60 | 0x21e2b60 | real_first_call |
| 37 | 153 | topUpIsolatedOnlyMargin | TopUpIsolatedOnlyMarginAction | 0x27594a0 | 0x21e2ee0 | 0x21e2ee0 | real_first_call |
| 38 | 154 | updateLeverage | UpdateLeverageAction | 0x2759fff | 0x21e0b70 | 0x21e0b70 | real_first_call |
| 39 | 155 | usdSend | UsdSendAction | 0x2759eb9 | 0x1f64a40 | 0x1f64a40 | real_first_call |
| 40 | 156 | ValidatorSignWithdrawal | ValidatorSignWithdrawalAction | 0x27598db | 0x374ec60 | 0x374ec60 | real_first_call |
| 41 | 157 | vaultDistribute | VaultDistributeAction | 0x2759b33 | 0x1e60020 | 0x1e60020 | real_first_call |
| 42 | 158 | vaultModify | VaultModifyAction | 0x2759f2f | 0x22c5fd0 | 0x22c5fd0 | real_first_call |
| 43 | 159 | vaultTransfer | VaultTransferAction | 0x27593d6 | 0x1e5fb20 | 0x1e5fb20 | real_first_call |
| 44 | 160 | VoteEthDeposit | VoteEthDepositAction | 0x2759751 | 0x1e5feb0 | 0x1e5feb0 | real_first_call |
| 45 | 161 | VoteEthFinalizedValidatorSetUpdate | VoteEthFinalizedValidatorSetUpdateAction | 0x2759e27 | 0x1e64cb0 | 0x1e64cb0 | real_first_call |
| 46 | 162 | VoteEthFinalizedWithdrawal | VoteEthFinalizedWithdrawalAction | 0x275a0fa | 0x27177c0 | 0x27177c0 | real_first_call |
| 47 | 163 | withdraw3 | Withdraw3Action | 0x27594e9 | 0x1f67810 | 0x1f67810 | real_first_call |
| 48 | 164 | VoteAppHash | VoteAppHashAction | 0x27597d8 | 0x1e5f5d0 | 0x1e5f5d0 | real_first_call |
| 49 | 165 | govPropose | GovProposeAction | 0x2759892 | 0x1f68be0 | 0x1f68be0 | real_first_call |
| 50 | 166 | govVote | GovVoteAction | 0x27593a9 | 0x1f64980 | 0x1f64980 | real_first_call |
| 51 | 167 | usdClassTransfer | UsdClassTransferAction | 0x275a2a2 | 0x1e60850 | 0x1e60850 | real_first_call |
| 52 | 168 | multiSig | MultiSigAction | 0x275a0cf | 0x282ee50 | 0x282ee50 | real_first_call |
| 53 | 169 | convertToMultiSigUser | ConvertToMultiSigUserAction | 0x27594cd | 0x1e64010 | 0x1e64010 | real_first_call |
| 54 | 170 | approveBuilderFee | ApproveBuilderFeeAction | 0x275a048 | 0x1e60a90 | 0x1e60a90 | real_first_call |
| 55 | 171 | startFeeTrial | StartFeeTrialAction | 0x275a0a2 | 0x21e00b0 | 0x21e00b0 | real_first_call |
| 56 | 172 | systemBole | SystemBoleAction | 0x2759516 | 0x1f69020 | 0x1f69020 | real_first_call |
| 57 | 173 | systemSpotSend | SystemSpotSendAction | 0x2759f13 | 0x1e5fcf0 | 0x1e5fcf0 | real_first_call |
| 58 | 174 | DeployerSendToEvmForFrozenUser | DeployerSendToEvmForFrozenUserAction | 0x2759805 | 0x1e64c20 | 0x1e64c20 | real_first_call |
| 59 | 175 | SystemUsdClassTransfer | SystemUsdClassTransferAction | 0x2759f5c | 0x1e64530 | 0x1e64530 | real_first_call |
| 60 | 176 | cSigner | CSignerAction | 0x2759937 | 0x21cfdd0 | 0x21cfdd0 | real_first_call |
| 61 | 177 | cWithdraw | CWithdrawAction | 0x2759bbd | 0x2758800 | 0x2758800 | real_first_call |
| 62 | 178 | cDeposit | CDepositAction | 0x2759ca3 | 0x1f65f80 | 0x1f65f80 | real_first_call |
| 63 | 179 | cUserModify | CUserModifyAction | 0x2759a68 | 0x3996230 | - | real_first_call_on_branch |
| 64 | 180 | reassessFees | ReassessFeesAction | 0x2759953 | 0x22ce180 | 0x22ce180 | real_first_call |
| 65 | 181 | evmUserModify | EvmUserModifyAction | 0x2759c76 | 0x22cd990 | 0x22cd990 | real_first_call |
| 66 | 182 | ReserveRequestWeight | ReserveRequestWeightAction | 0x2759403 | 0x2758ae0 | 0x2758ae0 | real_first_call |
| 67 | 183 | FinalizeEvmContract | FinalizeEvmContractAction | 0x2759735 | 0x22ce0d0 | 0x22ce0d0 | real_first_call |
| 68 | 184 | Hip3Deploy | Hip3DeployAction | 0x275a2eb | 0x21dd7e0 | 0x21dd7e0 | real_first_call |
| 69 | 185 | sendAsset | SendAssetAction | 0x2759687 | 0x1f678c0 | 0x1f678c0 | real_first_call |
| 70 | 186 | SystemApproveBuilderFee | SystemApproveBuilderFeeAction | 0x2759360 | 0x1e64620 | 0x1e64620 | real_first_call |
| 71 | 187 | SystemSendAsset | SystemSendAssetAction | 0x2759478 | 0x2728e10 | 0x2728e10 | real_first_call |
| 72 | 188 | SystemAlignedQuoteSupplyDelta | SystemAlignedQuoteSupplyDeltaAction | 0x275a075 | 0x1e64ac0 | 0x1e64ac0 | real_first_call |
| 73 | 189 | agentEnableDexAbstraction | AgentEnableDexAbstractionAction | 0x275a230 | 0x219a7a0 | 0x219a7a0 | real_first_call |
| 74 | 190 | userDexAbstraction | UserDexAbstractionAction | 0x275a286 | 0x1e60e00 | 0x1e60e00 | real_first_call |
| 75 | 191 | borrowLend | BoleAction | 0x2759543 | 0x2764b90 | 0x2764b90 | real_first_call |
| 76 | 192 | - | (no claim) | 0x2759b60 | - | 0x2729060 | unclaimed |
| 77 | 193 | - | (no claim) | 0x275938d | - | 0x1e611a0 | unclaimed |
| 78 | 194 | - | (no claim) | 0x275a2cf | - | 0x1e60f90 | unclaimed |
| 79 | 195 | - | (no claim) | 0x2759333 | - | 0x1e61110 | unclaimed |
| 80 | 196 | - | (no claim) | 0x275945c | - | 0x204c4e0 | unclaimed |
| 81 | 197 | - | (no claim) | 0x2759865 | - | 0x1e60bb0 | unclaimed |
| 82 | 198 | - | (no claim) | 0x2759821 | - | 0x27288c0 | unclaimed |
| 83 | 199 | - | (no claim) | 0x2759306 | - | 0x1e641e0 | unclaimed |
| 84 | 200 | - | (no claim) | 0x27592ea | - | 0x1e646c0 | unclaimed |
| 85 | 201 | - | (no claim) | 0x2759e54 | - | 0x27e3750 | unclaimed |
| 86 | 202 | - | (no claim) | 0x2759e9d | - | 0x1e648c0 | unclaimed |
| 87 | 203 | - | (no claim) | 0x275a259 | - | 0x1e5f010 | unclaimed |

## What this does not claim

- **Semantics.** It does not say what any handler does. Nothing was decompiled. Names, wire types and variants come from the reconstruction and are not checked against the binary.
- **Discriminant-to-wire-type mapping.** The `tag = 0x74 + index` relation and the order of the arms are measured. Whether the reconstruction's `case N` really is the serde variant N is taken from the reconstruction. No serde tables were decoded.
- **Withdrawal and bridge arms.** Cases 40, 46 and 47 are covered only for their entry mapping, meaning the arm and its first call. Their bodies are not analysed. The bridge / `requestWithdrawal` state machine belongs to other open PRs (#7, #8). Its addresses do not overlap this dispatcher.
- **Full function extent.** It says nothing about calls after the first one on each arm, about the shared tail at `0x275a180`/`0x275a186`, or about the unwind pad (`call _Unwind_Resume@plt` at `0x275a36b`).
- **Unclaimed cases 76..87.** Only their first-call target is recorded. They are not identified.
- **Other builds.** It applies to node #94 only.
- **Ordering.** It does not depend on PR #10 and was not based on it. If #10 lands first, the packet index may need a rebase.

## Rerun

Run as the repo user from the repo root.

    python3 -B tools/exchange_dispatch.py --out research/work-items/RE-010-exchange-handlers/exchange-dispatch.json
    python3 -I -B research/work-items/RE-010-exchange-handlers/verify.py
    python3 -O -B research/work-items/RE-010-exchange-handlers/verify.py
    python3 -B -m unittest tests.test_exchange_dispatch -v
    objdump -d --no-show-raw-insn -M intel --start-address=0x2759298 --stop-address=0x27592bd artifacts/node/94/hl-node

The output is sorted JSON, and it is byte-identical for any `PYTHONHASHSEED`. Its expected sha256 is pinned in the tests and in `MANIFEST.sha256`.

## Files

- `exchange-dispatch.json`: the per-case evidence, the address survey and the counts.
- `objdump-excerpts.txt`: binutils views of the bias/jump idiom, arm 0, case 63 and its branch, the case-5 wrapper, and the case-76 branch.
- `verify.py`: checks the manifest, recomputes the JSON, and compares it byte-for-byte against the committed file and against pinned counts.
