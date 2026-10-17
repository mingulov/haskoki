# Internal byte formats

These are Haskoki's request, snapshot, storage, and template encodings.
Ordinary PKCS#11 clients use the C ABI; they do not construct these frames.
The source definitions and tests below cover layouts, validation, and bounds.

Unless noted, `u8`/`u16`/`u32`/`u64` are unsigned big-endian integers of
that width; `len32` is a `u32` length followed by those bytes. Frames carry
owned values rather than caller pointers. Some encode numeric handles or
identities; each decoder checks its own lengths, tags, and ranges.

## Inventory

| # | Format | Crossing | Canonical definition | Pinning test |
|---|---|---|---|---|
| F1 | init frame | FFI/`Request.reqInput` → classic-init planners | §1 + `Codec.hs` header | `ByteFormatSpec` init golden + layout |
| F2 | verify one-shot frame | FFI/`reqInput` → verify planner | §1 + `Codec.hs` header | `ByteFormatSpec` verify golden |
| F3 | message frames (begin/next/one-shot) | FFI/`reqInput` → message planners | §1 + `Codec.hs` header | `ByteFormatSpec` message goldens + family gates |
| F4 | attribute frames (template entries, wanted lists, value codec, handles) | core-internal: `Object`/`Attribute` codecs ↔ planners; entries also decoded from scenario/detached bytes (the C→Haskell FFI template frame is F9, a different layout — not this encoding) | §2 + `Object.hs`/`Attribute.hs` | `ByteFormatSpec` template/value/wanted/handle goldens |
| F5 | recipe parameter codecs (the `params` tail of F1) | C `CK_MECHANISM` → FFI decode → recipe validators | §3 + per-`Recipe/*` module | `ByteFormatSpec` params goldens (+ per-recipe validity specs) |
| F6 | snapshot/portable bytes | save → bytes → restore (sessions, `haskoki-ctl` observable) | §4 + `Snapshot.hs` header grammar | `SnapshotSpec` golden + truncation/flip/no-pointer cases |
| F7 | SQLite store bytes (schema + JSON docs + blobs) | store file ↔ SQLite backend; memory backend shares the JSON docs | §5 + `spec/storage-schema.sql` | `StoreSpec` schema-shape pin + `BytesSpec` doc goldens + reload cases |
| F8 | proxy wire framing | none in-repo (external) | §6 ruling | n/a (C ABI crossing pinned by `layout_*` + `test-c-abi.sh`) |
| F9 | FFI template frame (C→Haskell) | every template-taking C entry (`std_CreateObject`, `std_CopyObject`, `std_FindObjectsInit`, `std_GenerateKey`, `std_GenerateKeyPair` ×2, `std_UnwrapKey`, `std_DeriveKey`) via `haskoki_std_pack_template` → `parseTemplateFrame` | §7 + `ffi/Haskoki/FFI/Standard.hs` + `cbits/standard_surface.h` | `StandardSurfaceSpec` frame cases (RV/empty/values/malformed/typed-faults) + native-encode + EC-params |

## 1. Request frames (`core/Haskoki/Operation/Codec.hs`)

`Request` carries one opaque input blob; these codecs frame the
structured arguments the planners need. Integers big-endian;
lengths exact (a short blob rejects; trailing bytes belong to the
documented tail field). Input blobs are already bounded by
`Haskoki.FFI.Decode.maxInputBytes`.

```
init:      mech:u64 permits:u16 flags:u8 params:bytes
verify1:   dlen:u32 data:dlen sig:bytes
begin:     plen:u32 params:plen aad:bytes
next:      tag:u8 ...
  cipher/sign: plen:u32 params:plen end:u8 part:bytes
  verify:      plen:u32 params:plen wflag:u8 [wlen:u32 witness:wlen] part:bytes
oneshot:   tag:u8 ...
  cipher: plen:u32 params:plen alen:u32 aad:alen input:bytes
  sign:   plen:u32 params:plen input:bytes
  verify: plen:u32 params:plen wlen:u32 witness:wlen input:bytes
```

Permit bits: 0 sign, 1 verify, 2 encrypt, 3 decrypt, 4
sign-recover, 5 verify-recover; bits 6–15 reserved, must be zero
(decoder rejects). Flag bit 0 is always-authenticate; bits 1–7
reserved, must be zero. Next/one-shot tags: 0 cipher, 1 sign, 2
verify; decoding is gated on the message family (a cipher-tagged
blob decodes under the encrypt/decrypt families only, and so on;
anything else rejects).

Container decoders: `decodeInitInput`, `decodeVerifyInput`,
`decodeMsgBegin`, `decodeMsgNext`, `decodeMsgOneShot` (all
`ByteString -> Maybe ...`). Pointer resolution: fixed-width
headers first, then length-delimited takes (`takeN` fails short);
the `params`/`sig`/`part`/`input` tails are opaque bytes carried,
never dereferenced. Trust story: blobs arrive from the FFI
boundary already length-bounded; the decoders additionally reject
reserved-bit abuse and family/tag mismatches, and permits decode
in canonical ascending order so equivalent permits compare equal.

## 2. Attribute frames (`core/Haskoki/Object.hs`, `core/Haskoki/Attribute.hs`)

Core-internal encoding — contrast F9 (§7): the C→Haskell frame
uses `u64le` type ids and little-endian values, while the
entries below use `tag:u8` ids and big-endian values;
`parseTemplateFrame` translates the former into the latter.

Template entry (order and duplicates preserved):

```
entry: tag:u8 vlen:u32 value:vlen
```

`tag` comes from the `AttributeType` enumerant (`attrTag = fromEnum`)
in [Attribute.hs](../core/Haskoki/Attribute.hs). Unknown tags reject;
at most `maxTemplateEntries` (64) entries decode. Use that enum and
`shapeOf` as the complete inventory instead of a separately maintained list.

Value codec (`encodeValue`/`decodeValue`):

```
bool:  1 byte, 0x00 or 0x01 (anything else rejects)
ulong: 8-byte big-endian over the whole Word64 domain
bytes: raw bytes, length <= maxAttributeBytes (4194304, 4 MiB)
```

Decoding validates the owning type's shape strictly
(`shapeOf`); a value with the wrong shape rejects before planning. Only label/application carry a text
contract (strict UTF-8 via `decodeTextAttribute`); every other
bytes-typed attribute is opaque binary.

Wanted lists (`encodeWanted`/`parseWanted`) are bare tag bytes.
Handles (`encodeHandle`/`decodeHandle`) are the handle number as
an unsigned long (8-byte big-endian), range-guarded to the
platform `Int` at decode.

Pointer resolution: none — tags index a closed enumerant table,
lengths are validated before splitting, values are owned bytes.
Trust story: templates arrive as F9 frames from FFI callers
(decoded by `parseTemplateFrame` into the entries above before
any planner acts) and from scenario files;
the entry-count bound, the value bound, the shape gate, and the
contradiction check (`validateTemplate`) all run before any
planner acts.

## 3. Recipe parameter codecs (F1 `params` tail)

One versioned codec per mechanism family (`name/version`, pinned
in `spec/mechanisms.json` routes and `dumpRegistry`):

| Codec | Layout | Example |
|---|---|---|
| `no-params/1` | empty (anything else rejects) | digest, plain HMAC, RSA v1.5 |
| `mac-general/1` | 8-byte big-endian tag length, 1..width | `GENERAL` HMAC/CMAC rows |
| `pss-params/1` | 3× 8-byte big-endian: digest code, MGF code, salt length (salt 0..64; digest must match the bound stem, generic rows take any table digest) | RSA-PSS rows |
| `sig-encoding/1` | `RAW`, `DER`, or empty (empty means `DER`) | ECDSA rows |
| `iv-bytes/1` | exactly `crIvBytes` raw bytes (CBC: one block; ECB: empty) | block-cipher rows |
| `oaep-params/1` | 2× 8-byte big-endian table codes (digest, MGF) + label bytes (possibly empty) | `CKM_RSA_PKCS_OAEP` |
| `hotp-params/1` | 2× 8-byte big-endian: counter, digit count (digits 6–8); translated from the caller's standard `CK_OTP_PARAMS` (counter entry required, output length optional, default 6) | `CKM_HOTP` |
| `ecdh-params/1`, `pbkd2-params/2`, `hkdf-params/3` | family params for derive ops (non-classic; never cross classic init) | KDF/ECDH rows |

Digest wire codes (PSS/OAEP shared convention): 1 MD5, 2 SHA_1, 3
SHA224, 4 SHA256, 5 SHA384, 6 SHA512, 7 SHA3_224, 8 SHA3_256, 9
SHA3_384, 10 SHA3_512, 11 RIPEMD160; code 0 never validates.
Decoders: per-`Recipe/*` `decode*Params` (strict widths, table
codes only). Trust story: these bytes originate as C
`CK_MECHANISM` parameters, are re-encoded by the FFI layer into
the canonical shapes above, and are re-validated against the
bound recipe at init (`checkMechParams`); unknown stems encode
but never validate.

## 4. Snapshot/portable bytes (`core/Haskoki/Snapshot.hs`)

Bounded versioned export/import of multipart operations
(`saveOperation`/`restoreOperation`). Magic `HKSNAP02` (schema id
plus format version `02`), then a `u8` profile tag (0 = 2.40, 1 =
3.0, 2 = 3.1, 3 = 3.2), a `u32` slot id, then a single/dual body
carrying mechanism, operation, parameters, buffered input, the
cipher chaining value, staged output, shape specs, auth marks,
and canonical key identities
(class/key-type/FNV-1a fingerprint — never resource ids,
pointers, or native handles). The full section grammar is the
`Snapshot.hs` module header (quoted here in skeleton; the header
is authoritative for field order).

Decoding is strict: truncated input, trailing bytes, unknown
tags, out-of-range values, incoherent kind/operation pairs, and
quota violations all reject; restore checks run decode, quotas,
profile, token, slot occupancy, then key binding, and any failure
returns the target session untouched. Key fingerprint: FNV-1a
over the stored material bytes (`fingerprintKey`, pinned value
in `BytesSpec`).

## 5. SQLite store bytes (`spec/storage-schema.sql`, `src/Haskoki/Runtime/Storage*`)

Schema (format version 3, `PRAGMA foreign_keys = ON`,
`journal_mode = DELETE`, `synchronous = EXTRA`, `busy_timeout =
5000`): `store_meta` (key/value incl. `schema_version = 3`),
`tokens` (id, 8-byte `slot_key`/`generation_key` blobs, token
`record_json`, `format_version = 1`), `objects` (id, token ref,
8-byte `class_key`, nullable 8-byte `key_type_key`,
`attributes_json`, `material_encoding`, nullable `material_blob`,
positive `revision`, `format_version = 1`), `detached_jobs`
(8-byte persistent id, token ref + generation key, function name,
execution state enum, `record_json`, `format_version = 1`),
`credentials` (token ref, `record_json` carrying base64
`so_pin`/`user_pin`, `format_version = 1`); plus
`objects_by_token` and `jobs_by_token` indexes. Full-width
unsigned quantities travel as 8-byte blobs or fixed hex text,
never as blind SQLite signed-integer casts. The Haskell backend
issues the same statements (`SQLite.hs` schema literals); the
`.sql` file is the readable reference, and the schema-shape pin
proves they agree.

History: version 1 has no `credentials` table; version 2 adds it
with in-band rows; version 3 freezes catalog PINs at migrate
(rowless tokens gain rows from the catalog, existing in-band rows
are kept byte-exact). Versions 1 and 2 refuse at open as
migration-required without writing a byte; only the explicit
`haskoki-ctl store migrate` moves them to 3. A wrong/future
`schema_version` is rejected without rewriting the database.

The store holds the current PINs in recoverable form: each
`credentials` row carries base64 `so_pin` and, when set, `user_pin`
(`user_pin` is nullable) with no hashing. Every `store migrate`
backup copies the pre-migration store bytes, so it holds those same
rows — a schema-1 backup has no `credentials` table yet, and a
token without a row has no PINs in the backup either; backups are
written 0600 and must be protected like the store itself.

JSON docs (canonical renderer: objects sort keys, no
whitespace): attribute values encode as JSON booleans (flags),
16-hex strings (ulongs), base64 strings (bytes); the object doc
carries `format_version`, hex `object_id`/`token_id`/`class`,
nullable hex `key_type`, the attrs object, `material_encoding`
(`none` or `attr-value/v1`), nullable base64 `material`, and hex
`revision`. Unknown names and cross-shape values fail decode. A
wrong/future `schema_version` is rejected without rewriting the
database.

## 6. Proxy transport

The proxy pair (`pkcs11-proxy-ng` daemon + shim) is maintained
externally (see [the parity driver](../scripts/test-proxy-parity.sh));
its wire framing (protobuf RPC) is owned by that project, and no
haskoki code parses or emits it. What crosses between our module
and the proxy is the C PKCS#11 ABI surface (function tables,
structs, scalar encodings), which is pinned by the `layout_*`
byte locks (`tests/c/layout_240.c` etc., run by
`scripts/test-c-abi.sh`) and the direct-vs-proxied parity
transcripts.
## 7. FFI template frame (C→Haskell)

The one frame every template-taking C entry speaks. The C side
flattens the caller's `CK_ATTRIBUTE` array into a malloc'd byte
frame; the Haskell side parses that frame back into typed
entries before any planner acts. Layout (`u64le` is a
little-endian 8-byte word; count, type, length, and native ulong
values use this order on the tested Linux amd64 ABI, unlike F4):

```
frame:  count:u64le record:count
record: type:u64le len:u64le value:len
```

The C packer `haskoki_std_pack_template` in
[standard_surface.c](../cbits/standard_surface.c) copies attribute values
into a flat allocation. It rejects a NULL array/value with nonzero count/
length, more than 64 attributes, values past 16 MiB, and oversized frames.

`parseTemplateFrame` and `readFrame` in
[Standard.hs](../ffi/Haskoki/FFI/Standard.hs) recheck the frame. They require
complete headers/records, exact consumption, at most 64 entries, known
attribute IDs, and valid typed values. Booleans use one byte (0 or 1);
native unsigned longs use eight little-endian bytes on this ABI; raw byte
values are bounded at 4 MiB. The generated attribute inventory maps IDs;
`decodeNativeValue` maps their values into the core representation.

`frameErrorRV` maps truncation/over-count to `CKR_ARGUMENTS_BAD`, unknown
types to `CKR_ATTRIBUTE_TYPE_INVALID`, and invalid values to
`CKR_TEMPLATE_INCONSISTENT`.
[StandardSurfaceSpec](../tests/model/StandardSurfaceSpec.hs) covers empty,
malformed, bounded, typed, and native-encoding cases. No caller pointer is
embedded in the copied frame.

### EC `CKA_EC_PARAMS` wire mapping (F9 sub-format)

`AttrEcParams` values translate between DER curve OIDs on the
wire and engine curve names inside, in both directions
(`ecParamsFromWire`; `ecParamsToWire`):

| Wire bytes (DER OID) | Engine name |
|---|---|
| `06 08 2A 86 48 CE 3D 03 01 07` | `P-256` |
| `06 05 2B 81 04 00 22` | `P-384` |
| `06 05 2B 81 04 00 23` | `P-521` |
| `06 03 2B 65 6E` | `X25519` |
| `06 03 2B 65 6F` | `X448` |

The table shows the prime/Montgomery subset; the full mapping
is the core `curveTable` plus `edwardsTable` plus
`montgomeryTable` (`Haskoki.Der`). The OID bytes are an
external standard (SEC2 prime curves in RFC 5480 §2.1.1 DER
encoding, Montgomery curves in RFC 8410), Haskoki tests its own translation table against those encodings.
Unknown inputs pass through both functions unchanged for the
engine to refuse (served curves execute; anything else the
engine refuses). Pin: `EC params map both ways`
(`caseEcParams`: all three curves each direction plus unknown
pass-through); the Montgomery rows pin both ways under
`Montgomery OID table agrees with the FFI`
(`caseMontgomeryTableAgreement`).
