# AEAD application journey

One symmetric AEAD round trip plus independent vector and
tag-negative tests, driven on the C surface by
`tests/c/consumer_aead.c` (run by `scripts/test-consumers.sh` in
direct mode and by `scripts/test-proxy-parity.sh` in both modes).
The journey uses AES-128-GCM with caller-supplied IV and AAD; the
token appends the tag to the ciphertext.

## Pinned vectors

The consumer replicates two engine-suite vectors byte-exactly
through the C surface. Both come from `caseAeadReal` and
`caseAeadEmptyPlaintext` in `tests/engine/OpenSSLSpec.hs`, whose
oracle root is Python cryptography AESGCM — quoted from the tree,
never from memory. Key `000102030405060708090a0b0c0d0e0f`, nonce
`000102030405060708090a0b`:

| Vector | AAD | Plaintext | Ciphertext | Tag |
| --- | --- | --- | --- | --- |
| one | `aad-data` | `Hello GCM world!` | `db09cba2093bb01706f216e544cf1429` | `39f0385041afdfd3a2d5a8e8ed69a2e6` |
| two | `aad-data` | empty | empty | `e01312146176abd643fcee9d4a640184` |
| three | none | empty | empty | `435b9ba12d75a4be8a977ea3cd011890` |

Each vector leg seals with `C_Encrypt` (expecting the exact
ciphertext length: 32, 16, 16 bytes), compares ciphertext and tag
bytes, then opens with `C_Decrypt` and expects the exact plaintext.
The fixed key arrives via `C_CreateObject` (`CKO_SECRET_KEY` plus
`CKK_AES` plus `CKA_VALUE`); keygen cannot supply exact bytes.

## Tag-negative matrix

Over the vector-one seal, each of these must fail closed with
`CKR_ENCRYPTED_DATA_INVALID`: flipped tag byte, flipped ciphertext
byte, changed AAD (`aad-datX`), flipped IV byte, short input (4
bytes), truncated input (31 bytes), and decryption under a
different imported key. A GCM failure is always this code, never
wrong plaintext.

## Tag-width sweep

Each approved SP 800-38D width — 128, 120, 112, 104, 96, 64, 32
bits — seals the 16-byte message to 16 bytes plus tag length and
opens back to the exact message. Widths outside this list never
seal (see below).

## Pinned refusals

- Provider-generated IV (`ulIvLen = 0`) refuses with
  `CKR_MECHANISM_PARAM_INVALID` (PKCS#11 v3.1 section 5.1.6: invalid
  parameters supplied to the mechanism).
- IV length/bits disagreement and off-list tag widths (for example
  16 bits) never seal; the consumer asserts the refusal and prints
  the observed code for the record.

## Application shape and limits

An application imports or generates an AES key, passes
`CK_AES_GCM_PARAMS` with caller IV (1..64 bytes, bit width
agreeing), AAD, and an approved tag width, then splits the returned
bytes into ciphertext plus trailing tag. One-shot calls buffer the
whole input; there is no generated-IV path and no streaming AEAD
promise. Multipart AEAD reachability is unclaimed: only the legs
above count as journey evidence.

## Evidence

The `native-aead` leg runs the compiled consumer against the
installed module with the native junction, in both profiles:

```sh
consumer_aead $MODULE
```

It expects exit 0 with `PASS: consumer_aead`. Evidence: pass P+I
([client-journeys.json](release-results/client-journeys.json)).
Evidence scope stays native-consumer: a direct C-surface receipt,
not an independent client. Every session leg uses the `crypto:`
prefix, so the parity driver excludes these lines from its
direct-vs-proxied diff while each mode still asserts every leg.
