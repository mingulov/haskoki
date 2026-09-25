# AES-CTS slice plan (CKM_AES_CTS via OpenSSL 4.0.2 provider CTS, test-first per task)

Target: 7500 `test_cts.py` legs (top KAT skip unit). PKCS#11 defines one
CKM_AES_CTS without naming the CBC-CS variant (the oracle itself says so
and auto-detects ours, running only the matching variant's vectors).
We implement CS1 (NIST SP 800-38A canonical first variant), raw-IV params
(`mech_bytes`, like CBC), one-shot `encrypt_single`/`decrypt_single`.
CS2/CS3 legs skip honestly by detector design.

0. Spike (no commit): provider CTS C probe — DONE, provider CTS is
   UNIMPLEMENTED in 4.0.2 (settable params lack `cts`/`cts_mode`;
   setting them is silently ignored; Final rejects partial blocks).
   Legacy flag skipped (bypasses our libctx discipline). DECISION:
   manual NIST CBC-CS1 over provider AES-ECB single-block (the
   construction a provider would run internally; AES primitive stays
   provider-sourced). Construction verified against ACVP vectors by
   harness, never by recall.
1. Shim `hsk_ossl4_cipher_cts` + header contract (fetch ciphername, CTS
   params, one-shot enc/dec; inlen > 16 else BADPARAM; outlen == inlen).
2. FFI `Raw.cipherCts` binding (mirror `cipherCbc`).
3. Engine `C_AES{128,192,256}_CTS` specs: fetch names, key/iv/length gates,
   runner, capability sets, notes, probes.
4. Driver CKM_AES_CTS route (raw-IV params) + synthetic route (classifier
   + caps; length rule at recipe level, shared by both backends).
5. Recipe params codec (iv/16) + length rule (>16B DATA_LEN_RANGE) +
   planner wiring (mirror CBC single-mulipart behavior).
6. Registry/catalog: flags [ENCRYPT, DECRYPT], routes, notes, evidence;
   regen + discovery/info pin updates (count stays 109).
7. Committed tests: engine ACVP-CS1 KATs (enc+dec × 128/192/256,
   aligned 32B + unaligned 33B + minimal 17B + multi-block), recipe
   specs, driver routing, planner gates (short input, bad IV),
   synthetic parity, C discovery updates.
8. Lanes: targeted CTS, fast, KAT with per-unit diffs; triage + docs.
9. Gates + triage commit(s).

Evidence bar: ACVP CS1 vectors as independent oracles (byte-exact ct);
detector legs (32B/33B × 3 key sizes) must pass; CS2/CS3 skip.
