# Claims and validation

Every proposed edit must be a JSONL claim with:

```json
{"claim_id":"fn_401000_name","kind":"function_name","target":"0x401000","proposed_value":"mw_config_parse_c2_list","confidence":"high","evidence":["xref string config","calls fopen/fgets","writes config struct offsets"],"status":"proposed"}
```

Supported claim kinds:
- `function_name`: meaningful behavior name for a function address.
- `function_signature`: C function declaration, keyed by function address.
- `local_variable_name`: name keyed by a target object with `function` (address string) and `identifier` (numeric Binary Ninja variable ID from the analyzed function’s HLIL variable list).
- `address_comment`: evidence-backed note keyed by instruction address.
- `function_comment`: concise evidence-backed behavior note.
- `data_name`: semantic name for a data address or symbol.
- `type_definition`: C type/enum/struct declaration.
- `source_file`: recovered source-tree assignment for addresses or symbols.

Use a hexadecimal virtual address for address-based targets, including the function field of a local-variable target.

## Naming

`snake_case`, and every renamed symbol carries the `mw_` prefix.

| Category | Pattern | Example |
|---|---|---|
| C2 | `mw_c2_<action>` | `mw_c2_send_beacon` |
| Persistence | `mw_persist_<method>` | `mw_persist_reg_run_key` |
| Evasion | `mw_evasion_<technique>` | `mw_evasion_check_debugger` |
| Credentials | `mw_cred_<target>` | `mw_cred_dump_lsass` |
| Crypto | `mw_crypto_<algo>` | `mw_crypto_xor_decrypt` |
| Collection | `mw_collect_<what>` | `mw_collect_screenshot` |
| Discovery | `mw_enum_<what>` | `mw_enum_processes` |
| Injection | `mw_inject_<method>` | `mw_inject_process_hollow` |
| Config | `mw_config_<action>` | `mw_config_parse_c2_list` |
| Utility | `mw_util_<purpose>` | `mw_util_resolve_api` |
| Strings | `mw_str_<action>` | `mw_str_deobfuscate` |
| Init | `mw_init_<what>` | `mw_init_comms` |

Variables: `mw_buf_<purpose>`, `mw_h_<target>`, `mw_<what>_size`. Data labels: `mw_encrypted_strings_blob`, `mw_c2_config_block`.

The prefix marks a symbol as analyst-supplied, so a glance at the symbol list separates recovered names from Binary Ninja's defaults and from real symbols the binary shipped with. Do not prefix names the binary already provided — an exported `main` or a DWARF-recovered Go symbol stays as it is.

**No `_likely` suffix.** Uncertainty lives in `claim.status` and the validator's `needs_human` verdict, not in the symbol name. A name is either supported by evidence and applied, or it is not applied — hedging in the identifier means every downstream reader inherits the doubt without the reasoning.

Avoid vague names like `handle_data`, `process_buffer`, `do_work`, or names copied from heuristics without code evidence.

## Validation Model

The validator must attack each claim before accepting it:
- Ask whether the evidence supports the exact name/type/comment, not just a related idea.
- Reject claims backed only by Malcat, YARA, capa, VirusTotal, MalwareBazaar, OTX, public-report text, or analyst intuition. `validate-claims` now enforces the all-lead-only case in code and fails the run; you still have to catch the mixed case, where one real code observation is padding for a heuristic hunch.
- Mark `needs_human` when two plausible interpretations have equal evidence.
- Require type claims to cite offset/size/access evidence, allocation size, ABI/API signatures, or consistent data-flow.
- Require function names to cite local code behavior: strings, imports, constants, xrefs, call graph position, data-flow, and side effects.
- Check the proposed name follows the `mw_` taxonomy and carries no `_likely` suffix. Check it says what the evidence says: `mw_c2_send_beacon` needs evidence of beaconing — periodicity, a check-in payload, a C2 endpoint — not merely that the function sends bytes. If the evidence supports `mw_c2_send_data`, reject and say so.
- Require source-tree claims to cite clusters: call relationships, shared state/types, common API families, or protocol boundaries.

Validator outputs go to `claims/verdicts.jsonl` with status `accepted`, `rejected`, or `needs_human`.
