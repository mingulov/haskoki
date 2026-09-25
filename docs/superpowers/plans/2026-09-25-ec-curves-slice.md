# EC curves slice plan (all oracle-collected curves, test-first per task)

Scope (user-approved): every curve the oracle collects for ECDSA/ECDH
wycheproof legs — 22 distinct curves, 19 new. The module carries the
curve on the key (CKA_EC_PARAMS OID), so no new mechanisms; this slice
widens key import, keygen, ECDSA sign/verify, and ECDH derive across
the full set. Weak sub-224-bit curves and binary curves are included
deliberately for maximal oracle coverage (marked as such at every
admission site); nothing here recommends them for production use.

Census (KAT r5, canonical data dir):
  ecdsa file: 29903 vectors; 22083 skipped, 5526 passed, 1306 xfailed
  ecdh file:  17558 vectors; 11209 skipped, 1749 passed, 170 xfailed
Have: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1).
New (19): secp224r1, secp224k1, secp256k1, secp192r1, secp192k1,
  secp160r1, secp160r2, secp160k1, brainpoolP224r1, brainpoolP256r1,
  brainpoolP320r1, brainpoolP384r1, brainpoolP512r1, sect283k1,
  sect283r1, sect409k1, sect409r1, sect571k1, sect571r1.
Projected conversion: ~29k skip legs become runs; hash/mechanism-gated
legs (if any) stay honestly skipped and get attributed per unit.

Label space: internal curve names are exactly the OpenSSL group names
(the EC keygen shim passes the name to OSSL_PKEY_PARAM_GROUP_NAME, and
"provider=default" serves all of them):
  P-256, P-384, P-521 (kept), secp224r1, secp224k1, secp256k1,
  secp192r1, secp192k1, secp160r1, secp160r2, secp160k1,
  brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1,
  brainpoolP512r1, sect283k1, sect283r1, sect409k1, sect409r1,
  sect571k1, sect571r1.

OID table (DER, tag+length included; every byte verified against the
oracle's own table in pkcs11_check/raw/ec.py — the brainpoolP224r1
tail byte is 0x05, RFC 5639; the 0x0C lookalike is the twisted
variant and must NOT be used):
  secp160r1      06 05 2B 81 04 00 08            coord 20  WEAK
  secp160r2      06 05 2B 81 04 00 1E            coord 20  WEAK
  secp160k1      06 05 2B 81 04 00 09            coord 20  WEAK
  secp192k1      06 05 2B 81 04 00 1F            coord 24  WEAK
  secp192r1      06 08 2A 86 48 CE 3D 03 01 01   coord 24  WEAK
  secp224k1      06 05 2B 81 04 00 20            coord 28
  secp224r1      06 05 2B 81 04 00 21            coord 28
  secp256k1      06 05 2B 81 04 00 0A            coord 32
  brainpoolP224r1 06 09 2B 24 03 03 02 08 01 01 05  coord 28
  brainpoolP256r1 06 09 2B 24 03 03 02 08 01 01 07  coord 32
  brainpoolP320r1 06 09 2B 24 03 03 02 08 01 01 09  coord 40
  brainpoolP384r1 06 09 2B 24 03 03 02 08 01 01 0B  coord 48
  brainpoolP512r1 06 09 2B 24 03 03 02 08 01 01 0D  coord 64
  sect283k1      06 05 2B 81 04 00 10            coord 36  BINARY
  sect283r1      06 05 2B 81 04 00 11            coord 36  BINARY
  sect409k1      06 05 2B 81 04 00 24            coord 52  BINARY
  sect409r1      06 05 2B 81 04 00 25            coord 52  BINARY
  sect571k1      06 05 2B 81 04 00 26            coord 72  BINARY
  sect571r1      06 05 2B 81 04 00 27            coord 72  BINARY
Bare-point lengths (0x04 || X || Y): 41, 49, 57, 65, 73, 81, 97,
105, 129, 133, 145. Lengths COLLIDE across curves (65 = P-256 /
secp256k1 / brainpoolP256r1; 57 = secp224r1 / secp224k1 /
brainpoolP224r1; 97 = P-384 / brainpoolP384r1; 43/49/73/105/145
similarly). Max coord width becomes 72 (sect571), not 66.

Design decisions (locked):
- ECDH peer check goes width-based. ecdhPeerCurve's exact-label-from-
  length contract is unimplementable once lengths collide; it is
  replaced by ecdhPeerWidth (SPKI OID scan, else bare-point width)
  and the engine gates base-width == peer-width. The C shim stays
  the final arbiter (on-curve membership). RecipeEcdhSpec pins are
  updated to the new contract with this rationale cited.
- ecdhSecretWidth gains all widths (max 72); Derive planner caps and
  every "66-byte maximum" comment/prose move to 72 with reason.
- C shim buffers sized P-521-max (1+2*66) grow to sect571-max
  (1+2*72); audit every fixed EC buffer in ossl4_ctx.c.
- Synthetic backend: classSignFor already domain-separates by full
  spec, so new curves need allowlist + name-list extension only
  (no new crypto); new golden labels for new curves (t06-* goldens
  are frozen and must NOT churn).
- secp224k1 watch: the oracle encodes its r||s at 29-byte halves
  (coord_size 29 in _ECDSA_CONFIGS); the shim splits input halves
  and range-checks, which should admit them — valid-vector legs
  adjudicate, and a false-reject cluster reopens the split rule.
- Cofactor ECDH on h=2 curves (sect283k1/sect409k1/sect571k1) rides
  the existing cofactor flag into OpenSSL; vectors adjudicate.
- Maximal-coverage comments mark every weak/binary admission
  (Der.hs table, recipe scans, ecCurveOf, t16EcdsaCurves).
- This plan itself complies with check-history-codes.py (no Slice
  headers, no red/green verdict words, no task codes).

Tasks (test-first each: spec fails for the right reason, then
implement, then the focused suite passes):
1. Der.hs OID table + coord widths + Der specs (all 22 OIDs).
2. Ecdsa.hs ecdsaCurveOfDer needles + RecipeEcdsaSpec (22 curves).
3. Ecdh.hs ecdhSecretWidth + ecdhPeerWidth (new) + RecipeEcdhSpec
   contract update (width-based, collision cases pinned).
4. Standard.hs ecParamsFromWire/ecParamsToWire + round-trip specs.
5. KeyManagement.hs ecCurveOf allowlist + keygen curve specs.
6. Backend.hs ecdsaSigCap + OpenSSL4.hs t16EcdsaCurves + engine
   gates/strings + ECDH width gate + Engine specs.
7. ossl4_ctx.c buffer audit (72B) + binary-curve verify path + C tests.
8. Synthetic.hs allowlists + name lists + note string + new goldens.
9. OpenSSLSpec interop vectors for new curves (pinned-CLI pattern).
10. mechanisms.json honesty notes (curve prose) + doc regen.
11. Lanes: targeted ECDSA/ECDH, then fast + KAT with per-unit diffs.
12. Gates + triage commit (fast r23 / KAT r6 entries attributed).

Adjudication: valid vectors must pass; invalid must reject with the
pinned codes; conversions are per-unit attributed vs r22b/r5; any
new failure or xpass stops the slice for root-cause.
