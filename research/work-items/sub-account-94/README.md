# Sub-Account Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/sub_account.rs` extracted from `artifacts/node/94/hl-node`
(SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`). Zero binary execution; offline ELF analysis only.

Names and error labels are inferred; numeric bytes and local predicates are observed. The models cover only equity/count and UTF-8 byte-length predicates, not full admission or uniqueness. Original padded spans and exports are preserved in `../RE-001-nxtlvlfirm-review-20261031/original-submissions/615/`.

## Subsystem Extents
Total verified routine footprint: **11 FDEs**, **6,903 bytes**.

| Routine | Start | End | Size | SHA-256 |
|---|---|---|---|---|
| `SubAccounts::create_sub_account_with_address` | `0x36f3610` | `0x36f3c15` | 1541 B | `57d9433443acfdcd5eaaa3836cd47709b12214b865da557db5ed977b9ac3f068` |
| `SubAccountAddressDeriver::derive_sub_account_user` | `0x36f3c20` | `0x36f3ed0` | 688 B | `805350d89fc7286539c1d5a7739eabc12c9896dbecec8c9933dc27e3810dd06e` |
| `SubAccounts::lookup_master` | `0x36f3ed0` | `0x36f3fd1` | 257 B | `7173ed32bc1c068900e1a756332a573f32acdb8039d90fa99af844c4ac73ba51` |
| `SubAccounts::is_sub_account_user` | `0x36f3fe0` | `0x36f40cd` | 237 B | `86c57d73478a3158a4f600af534816cbfb65cbf0b53acce61125d06de8728e8a` |
| `SubAccounts::modify_sub_account_name` | `0x36f40d0` | `0x36f43bc` | 748 B | `fc0504af35fef45e5e3dd2381eda4382f7654760ac495de84876f587810d2248` |
| `SubAccounts::validate_new_name` | `0x36f43c0` | `0x36f4627` | 615 B | `20479604d0e6d4fd5ea2de0cef68d10e6183721bcf8bbb4343a0127554338b3f` |
| `SubAccountEntry::serialize_json` | `0x36f4630` | `0x36f4964` | 820 B | `1dfdfbbdd41c15ea5c2437e235516de65be1794cfadb50c63722336c510dba5a` |
| `SubAccountEntry::serialize_msgpack` | `0x36f4970` | `0x36f4c46` | 726 B | `5e970148cb0466c05991731a3010fa735315d81b15b35ab78ae61095b4138331` |
| `SubAccountEntry::serialize_visitor` | `0x36f4c50` | `0x36f4dec` | 412 B | `72a6376223f9eb1b84c904324eeb8a975e76317bcbf78c5ad964e0652c5220a2` |
| `SubAccountEntry::serialize_helper` | `0x36f4df0` | `0x36f4e73` | 131 B | `cc35c4e1b912086cf40b2b6f9d89bb340e549c9091230046aed6e21965a49e83` |
| `SubAccounts::serialize_json` | `0x36f4e80` | `0x36f5158` | 728 B | `cef7adb6007357d1e653746e007bfe31a3831e865f2f5dab7971fc4b47152df1` |

## Panic Records
- `0x56f1c38`: `/home/ubuntu/hl/code_Mainnet/l1/src/sub_account.rs:69:13` (referenced at `0x36f3bcd`)

## Key Constants & Limits
- `CREATE_SUB_ACCOUNT_DOMAIN`: `"createSubAccount"` (literal domain at `0x2035a0`)
- `MIN_CREATE_EQUITY_RAW`: `10,000,000` (`0x989680` at `0x36f3627`)
- `DISPLAY_USD_DIVISOR`: `100.0` (at `0x20a960`)
- `SUB_ACCOUNT_CAP_EQUITY_STEP_RAW`: `10,000,000_000` (magic mul `0xdbe6fecebdedd5bf >> 33` at `0x36f3734`)
- `SUB_ACCOUNT_CAP_BASE`: `10` (`0xa` at `0x36f3755`)
- `SUB_ACCOUNT_CAP_MAX_BONUS`: `40` (`0x28` at `0x36f3748`)
- `MAX_NAME_BYTES`: `16` (`0x10` at `0x36f43d1`)
- `MAX_WIRE_NAME_BYTES`: `100` (`0x64` at `0x36f390c`)

## Observed codes and inferred labels
- `SUCCESS_CODE = 390` (`0x186`)
- `ERR_TOO_MANY_SUB_ACCOUNTS = 214` (`0xd6`)
- `ERR_SUB_ACCOUNT_NAME_NOT_UNIQUE = 215` (`0xd7`)
- `ERR_DUPLICATE_SUB_ACCOUNT_USER = 216` (`0xd8`)
- `ERR_SUB_ACCOUNT_INVALID_NAME = 217` (`0xd9`)
- Unverified reference label outside these controls: `ERR_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED = 218` (`0xda`)
- Unverified reference label outside these controls: `ERR_SUB_ACCOUNT_NOT_ALLOWED = 219` (`0xdb`)
- `ERR_SUB_ACCOUNT_NOT_REGISTERED = 220` (`0xdc`)
- `ERR_SUB_ACCOUNTS_NOT_ELIGIBLE = 221` (`0xdd`)
- Unverified reference label outside these controls: `ERR_SELF_TRANSFER = 222` (`0xde`)
- `ERR_FULL_NAME_TOO_LONG = 323` (`0x143`)
