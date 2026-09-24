#!/usr/bin/env python3
"""Generate the complete mechanism catalog from the byte-locked headers.

Reads:
  spec/sources.lock.json          byte lock (the single input header)
  spec/vendor/pkcs11.h         pinned latchset public-domain header
                                  (IDs + aliases)
  spec/mechanisms.json            existing file (reviewed/behavior rows are
                                  PRESERVED; only header-derived fields are
                                  refreshed, and a numeric-ID mismatch fails)

Writes (deterministic bytes, no timestamps):
  spec/mechanisms.json            ALL 464 canonical CKM entries (480 names
                                  with aliases), sorted by (value, name)
  core/Haskoki/Registry/Generated.hs
                                  generated inventory table consumed by
                                  Haskoki.Registry.curatedRegistry, so the
                                  Haskell registry matches the JSON catalog
                                  without hand-typed numeric IDs
  cbits/mech_catalog.inc          real-tested mechanism rows for the
                                  standard C surface (C_GetMechanismList /
                                  C_GetMechanismInfo), ascending id

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/generate-mechanisms.py

Catalog entry != behavior: generated rows are catalog-only (behavior
planned, empty routes, unreviewed mechanism info). Behavior rows are
promoted by later slices, which edit the JSON's reviewed fields; this
generator preserves those edits by canonical name and only refreshes
the header-derived fields (numeric_id, aliases,
source_refs), failing loudly if a preserved numeric_id disagrees with
the headers.

Family is a NAME-SHAPE grouping hint for recipe planning, not a
behavior claim. The classifier below is deterministic and documented;
anything it cannot place lands in "special" (needs an individual
recipe), never in a guessed behavior family.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hdr_parse  # noqa: E402
import mech_catalog  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "spec"
MECH_PATH = SPEC / "mechanisms.json"
HS_PATH = REPO / "core" / "Haskoki" / "Registry" / "Generated.hs"

# The single locked source (spec/sources.lock.json): every row cites it.
SOURCE_ID, SOURCE_PATH = hdr_parse.selected_header()

# (family, [substring patterns]) in FIRST-MATCH order. Every pattern
# was grounded against the 3.2 header set; the generator prints
# the histogram. Order matters: pair/key generation first (template-driven
# shape regardless of algorithm), then wrap/KEM/AEAD/derive/MAC (which
# share substrings with the algorithm families below them), then the
# algorithm families, then the small special-shape groups.
FAMILY_RULES = [
    ("keypair", ["_KEY_PAIR_GEN"]),
    ("keygen", ["_KEY_GEN"]),
    ("wrap", ["WRAP"]),
    ("kem", ["ENCAPS", "ML_KEM", "CKM_KEM"]),
    ("aead", ["_GCM", "_CCM", "CHACHA20_POLY1305", "SALSA20_POLY1305",
                "_EAX", "_OCB"]),
    ("derive", ["KEY_DERIVATION", "KEY_DERIVE", "DERIVE", "KDF", "PRF",
                "HKDF", "PBKDF", "PKCS5_PBKD", "ECDH", "MQV", "X9_42",
                "X9_63", "KEA", "SP800_108", "SSKDF", "TLS12_KDF",
                "TLS_KDF"]),
    ("mac", ["_HMAC", "_CMAC", "_GMAC", "_XCBC", "POLY1305", "SIPHASH",
             "_MAC", "KMAC", "CBCMAC"]),
    ("cipher", ["_ECB", "_CBC", "_CTR", "_CFB", "_OFB", "_CTS", "_XTS",
                "_PAD", "CHACHA", "SALSA", "PBE_", "RC4", "RC2", "RC5",
                "DES", "AES", "CAMELLIA", "ARIA", "SEED", "CAST",
                "IDEA", "BLOWFISH", "TWOFISH", "SKIPJACK", "BATON",
                "JUNIPER", "KASUMI", "MISTY", "GOST28147", "SM4",
                "CDMF", "FEAL", "SAFER", "XOR", "VIGENERE", "ONE_TIME_PAD",
                "DOUBLE_DES", "DES2_", "DES3_", "CBC_ENCRYPT_DATA"]),
    ("rsa", ["RSA"]),
    ("ec", ["ECDSA", "_EC_", "CKM_EC", "EDDSA", "EDWARDS", "MONTGOMERY",
            "X25519", "X448", "ECNR", "ECKCDSA", "DLIES", "ECIES",
            "GOSTR3410", "SM2"]),
    ("pqc", ["ML_DSA", "SLH_DSA", "DILITHIUM", "FALCON", "SPHINCS"]),
    ("dsa", ["DSA", "FIPS_G_GEN"]),
    ("digest", ["DIGEST", "MD2", "MD5", "SHA1", "SHA_1", "SHA224",
                "SHA256", "SHA384", "SHA512", "SHA3_", "SHAKE",
                "BLAKE2", "HAS160", "RIPEMD", "GOSTR3411", "SM3",
                "SKEIN", "FASTHASH"]),
    ("otp", ["HOTP", "TOTP", "OCRA", "SECURID"]),
    ("stateful", ["HSS", "XMSS", "_LMS", "LMS_"]),
]


def fail(msg):
    print(f"generate-mechanisms: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def classify(name):
    for family, patterns in FAMILY_RULES:
        for pat in patterns:
            if pat in name:
                return family
    return "special"


def fmt_id(value):
    return "0x%08x" % value


GENERATED_NOTE = ("Catalog-only (generator note): name-shape family hint "
                  "only; mechanism info unreviewed; no behavior, synthetic, "
                  "or real route. See spec/source-issues.json.")
DEFAULT_SUPPORT = {
    "abi": "planned",
    "behavior": "planned",
    "synthetic": "planned",
    "real": "planned",
    "recovery": "not-applicable",
}


def is_promoted(old):
    """A row is promoted (preserved verbatim, header-fields verified)
    once a behavior slice touches its reviewed fields: non-default
    support, any routes or evidence, or notes that differ from the
    generated template by even a byte (exact match, so honesty notes
    appended to planned rows persist; if the template text ever
    changes, every row conservatively preserves and the migration is
    explicit). Pure generator rows are refreshed wholesale so
    classifier improvements apply; the family field is
    generator-owned until promotion."""
    if old.get("support") != DEFAULT_SUPPORT:
        return True
    if old.get("routes"):
        return True
    if old.get("test_evidence"):
        return True
    if old.get("notes", "") != GENERATED_NOTE:
        return True
    return False


def source_refs(entry, provenance):
    name = entry["name"]
    if name not in provenance:
        fail(f"{name}: canonical spelling not defined in {SOURCE_PATH}")
    if provenance[name]["value"] != entry["value"]:
        fail(f"{name}: canonical value disagrees with {SOURCE_PATH}")
    return [{"section": f"pkcs11.h:{name}",
             "source_id": SOURCE_ID}]


def generated_row(entry, provenance):
    name, value = entry["name"], entry["value"]
    return {
        "numeric_id": fmt_id(value),
        "canonical_name": name,
        "aliases": list(entry["aliases"]),
        "source_refs": source_refs(entry, provenance),
        "family": classify(name),
        "mechanism_info": {
            "flags": [],
            "key_size_unit": "mechanism-specific",
            "min_key_size": 0,
            "max_key_size": 0,
        },
        "routes": [],
        "support": {
            "abi": "planned",
            "behavior": "planned",
            "synthetic": "planned",
            "real": "planned",
            "recovery": "not-applicable",
        },
        "test_evidence": [],
        "notes": GENERATED_NOTE,
    }


def refresh_preserved(old, entry, provenance):
    """Verify (never silently rewrite) the header-derived fields of a
    preserved (reviewed/behavior) row against the parsed headers."""
    name = entry["name"]
    want_id = fmt_id(entry["value"])
    if old.get("numeric_id") != want_id:
        fail(f"{name}: preserved numeric_id {old.get('numeric_id')} != "
             f"header {want_id}")
    if old.get("canonical_name") != name:
        fail(f"canonical_name mismatch for {name}")
    old_aliases = old.get("aliases", [])
    if sorted(old_aliases) != sorted(entry["aliases"]):
        fail(f"{name}: preserved aliases {old_aliases} != header "
             f"{entry['aliases']} (alias drift must be reviewed, not "
             f"silently rewritten)")
    # Preserved source ref is the single canonical citation of the
    # locked header; any drift fails loudly for review.
    want_refs = [{"section": f"pkcs11.h:{name}",
                  "source_id": SOURCE_ID}]
    if old.get("source_refs") != want_refs:
        fail(f"{name}: preserved source_refs {old.get('source_refs')} != "
             f"header {want_refs} (ref drift must be reviewed, not "
             f"silently rewritten)")
    return old


HS_PREAMBLE = '''{- | Generated mechanism inventory.

GENERATED by @scripts/generate-mechanisms.py@ from the byte-locked
headers; do not edit by hand. Re-run the generator to refresh.

One row per canonical @CKM_*@ mechanism: numeric id, canonical name,
and alias names. 'Haskoki.Registry.curatedRegistry' folds these rows
into its inventory projection so the Haskell registry and
@spec/mechanisms.json@ share one machine-derived source for numeric
IDs. Behavior descriptors stay hand-reviewed in 'Haskoki.Registry';
only identity (id and names) is generated here.

The name lookups let production code resolve mechanism ids without
hand-typed numerics; every name production resolves is
pinned by TemplateRulesSpec and cross-checked against the headers by
@scripts/check-denominators.py@.

The @ckm_*@ named constants give one total binding per
canonical mechanism: static call sites resolve ids through these,
never through a partial name lookup.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Registry.Generated
  ( generatedInventory
  , generatedIdByName
  , mustGeneratedId
'''

HS_EXPORT_TAIL = '''  ) where

import Data.Text (Text)
import Data.Word (Word64)

-- | Full header inventory: @(numeric id, canonical name, aliases)@,
-- ascending by id. 464 rows covering all 480 header CKM names.
generatedInventory :: [(Word64, Text, [Text])]
generatedInventory =
'''


def hs_escape(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')


def const_name(canonical):
    # CKM_AES_CBC -> ckm_AES_CBC (injective: canonical names are unique).
    assert canonical.startswith("CKM_"), canonical
    return "ckm_" + canonical[len("CKM_"):]


def render_hs(entries):
    lines = [HS_PREAMBLE.rstrip("\n")]
    for e in entries:
        lines.append(f"  , {const_name(e['name'])}")
    lines.append(HS_EXPORT_TAIL.rstrip("\n"))
    rows = []
    for e in entries:
        aliases = ", ".join(f'"{hs_escape(a)}"' for a in e["aliases"])
        rows.append(f'  (0x{e["value"]:x}, "{hs_escape(e["name"])}", [{aliases}])')
    lines.append("  [ " + rows[0].strip() if rows else "  [ ]")
    for r in rows[1:]:
        lines.append("  , " + r.strip())
    lines.append("  ]")
    lines.append("")
    lines.append("-- | Resolve a canonical or alias mechanism name to its id.")
    lines.append("generatedIdByName :: Text -> Maybe Word64")
    lines.append("generatedIdByName name =")
    lines.append("  case lookup name [(n, w) | (w, n, _) <- generatedInventory] of")
    lines.append("    Just w -> Just w")
    lines.append("    Nothing ->")
    lines.append("      lookup name [(a, w) | (w, _, als) <- generatedInventory, a <- als]")
    lines.append("")
    lines.append("-- | Resolve a generated id by name. PARTIAL: calls 'error' on unknown text;")
    lines.append("-- static call sites use the generated 'ckm_*' constants instead,")
    lines.append("-- dynamic lookup stays explicitly fallible via 'generatedIdByName'.")
    lines.append("mustGeneratedId :: Text -> Word64")
    lines.append("mustGeneratedId name = case generatedIdByName name of")
    lines.append("  Just w -> w")
    lines.append('  Nothing -> error ("mustGeneratedId: unknown " ++ show name)')
    lines.append("")
    lines.append("-- | Named mechanism ids, one per canonical inventory row.")
    lines.append("-- Total bindings: no lookup, no failure mode.")
    for e in entries:
        c = const_name(e["name"])
        lines.append(f"{c} :: Word64")
        lines.append(f"{c} = 0x{e['value']:x}")
    return "\n".join(lines) + "\n"


def main():
    tables, provenance = hdr_parse.catalog_tables()
    entries = tables["CKM_"]
    old_rows = {}
    if MECH_PATH.exists():
        try:
            old_data = json.loads(MECH_PATH.read_text())
        except Exception as e:  # noqa: BLE001 - reported, not hidden
            fail(f"cannot parse {MECH_PATH}: {e}")
        for m in old_data.get("mechanisms", []):
            old_rows[m["canonical_name"]] = m
    else:
        fail(f"{MECH_PATH} missing: refusing to generate without the "
             f"reviewed anchor rows (restore the file first)")
    out, preserved, fresh, refreshed = [], 0, 0, 0
    for e in entries:
        if e["name"] in old_rows and is_promoted(old_rows[e["name"]]):
            out.append(refresh_preserved(old_rows[e["name"]], e, provenance))
            preserved += 1
        else:
            if e["name"] in old_rows:
                refreshed += 1
            else:
                fresh += 1
            out.append(generated_row(e, provenance))
    dropped = sorted(set(old_rows) - {e["name"] for e in entries})
    if dropped:
        fail(f"existing rows vanished from headers (review before "
             f"dropping): {dropped}")
    # Deterministic bytes: sort_keys + indent=2 + trailing newline,
    # matching the existing file's conventions.
    doc = {
        "mechanisms": out,
        "schema_version": 1,
        "status": "reviewed-source-of-truth",
        "provenance": ("Reviewed rows preserved verbatim; "
                       "remaining rows generated catalog-only entries "
                       "from the byte-locked headers. Catalog entry != "
                       "behavior: only rows with behavior:tested plus "
                       "test_evidence execute anywhere."),
    }
    # NOTE: top-level key order is insertion order (mechanisms first),
    # matching the reviewed anchor file; entry keys are alphabetical.
    doc["mechanisms"] = [
        {k: m[k] for k in sorted(m)} for m in out
    ]
    doc = {k: doc[k] for k in ("mechanisms", "schema_version", "status", "provenance")}
    text = json.dumps(doc, indent=2) + "\n"
    MECH_PATH.write_text(text)
    HS_PATH.parent.mkdir(parents=True, exist_ok=True)
    HS_PATH.write_text(render_hs(entries))
    # The C mechanism catalog for the standard surface (the
    # real-tested projection of the rows just written).
    inc_text = mech_catalog.render_inc(
        mech_catalog.real_tested_rows(doc["mechanisms"]))
    mech_catalog.INC_PATH.write_text(inc_text)
    # Family histogram to stdout (review aid, not a file).
    hist = {}
    specials = []
    for m in out:
        hist[m["family"]] = hist.get(m["family"], 0) + 1
        if m["family"] == "special":
            specials.append(m["canonical_name"])
    print(f"generate-mechanisms: {len(out)} entries "
          f"({preserved} preserved, {fresh} generated, {refreshed} refreshed)")
    for fam in sorted(hist):
        print(f"  family {fam}: {hist[fam]}")
    print(f"  special members ({len(specials)}):")
    for name in specials:
        print(f"    {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
