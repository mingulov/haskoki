/* tests/c/consumer_certlink.c — certificate-linked identity journey.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives the linked certificate/key
 * identity through the pinned 3.2 headers:
 *   - the real fixture DER (tests/fixtures/cert-selfsigned.der,
 *     SHA-256 pinned, no embedded synthetic bytes) becomes an X.509
 *     certificate object with DER-derived subject and serial bytes;
 *     an EC P-256 pair mints with the same CKA_ID, and the
 *     certificate takes that ID after creation
 *   - find-by-ID returns exactly the three linked handles;
 *     find-by-absent-ID returns none; VALUE and SUBJECT read back
 *     the stored bytes; the untyped CKA_HASH_OF_CERTIFICATE reads
 *     refused with CKR_ATTRIBUTE_TYPE_INVALID, an unavailable
 *     length, and the caller's buffer untouched
 *   - the linked key signs an application message and the linked
 *     public key verifies it; a tampered message and the wrong
 *     public key both refuse with CKR_SIGNATURE_INVALID
 *   - the same linkage persists as token objects in a SQLite store
 *     across a finalize/re-initialize restart, then destroys cleanly
 *
 * The link-ID bytes {0x01, 0x01} deliberately match the CLI journeys
 * (docs/client-portfolio.md), where OpenSC creates the persisted key
 * under --id 0101 and GnuTLS uses it.
 *
 * Topology: the memory interval runs identically in direct and
 * proxy modes, while the SQLite restart intervals are direct-only
 * (the client cannot switch the daemon backend, and client
 * reattach is not a backend restart); proxy mode skips them with a
 * loud note. Every session-touching leg uses the "crypto:" prefix
 * so the parity script excludes these lines from its
 * direct-vs-proxied diff while the legs themselves assert strictly
 * per mode.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard). The SHA-256 and DER walker
 * below are small TU-local copies of the proven logic in
 * tests/c/consumer_certificates.c (independent TUs share no headers).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_certlink <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("ok: ");                                                      \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Topology-scoped checks: prefixed so the parity script excludes them
 * from its direct-vs-proxied diff; the legs assert strictly per mode. */
#define CHECKC(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("crypto: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("crypto: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

static void setup_error(const char *msg) {
  fprintf(stderr, "certlink setup: %s\n", msg);
  exit(2);
}

/* Compact SHA-256 (FIPS 180-4) for the fixture pin. */
static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void sha256(const CK_BYTE *msg, size_t len, CK_BYTE out[32]) {
  static const uint32_t k[64] = {0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL,
    0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL,
    0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
    0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL,
    0x76f988daUL, 0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 0x27b70a85UL,
    0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL,
    0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL,
    0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL,
    0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL,
    0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL,
    0xc67178f2UL};
  uint32_t h[8] = {0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL};
  size_t off = 0;
  uint64_t bitlen = (uint64_t)len * 8;
  CK_BYTE block[64];
  while (off + 64 <= len) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
      w[i] = ((uint32_t)msg[off + 4 * i] << 24) | ((uint32_t)msg[off + 4 * i + 1] << 16) |
        ((uint32_t)msg[off + 4 * i + 2] << 8) | (uint32_t)msg[off + 4 * i + 3];
    for (unsigned i = 16; i < 64; ++i) {
      uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
      hh = h[7];
    for (unsigned i = 0; i < 64; ++i) {
      uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + s1 + ch + k[i] + w[i];
      uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g;
    h[7] += hh;
    off += 64;
  }
  size_t rem = len - off;
  memset(block, 0, sizeof block);
  memcpy(block, msg + off, rem);
  block[rem] = 0x80;
  if (rem >= 56) {
    for (unsigned r = 0; r < 2; ++r) {
      uint32_t w[64];
      for (unsigned i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
          ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
      for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
      }
      uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
        hh = h[7];
      for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g;
      h[7] += hh;
      if (r == 0) {
        memset(block, 0, sizeof block);
        for (unsigned i = 0; i < 8; ++i) block[56 + i] = (CK_BYTE)(bitlen >> (56 - 8 * i));
      }
    }
  } else {
    for (unsigned i = 0; i < 8; ++i) block[56 + i] = (CK_BYTE)(bitlen >> (56 - 8 * i));
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
      w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
        ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    for (unsigned i = 16; i < 64; ++i) {
      uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
      hh = h[7];
    for (unsigned i = 0; i < 64; ++i) {
      uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + s1 + ch + k[i] + w[i];
      uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g;
    h[7] += hh;
  }
  for (unsigned i = 0; i < 8; ++i) {
    out[4 * i] = (CK_BYTE)(h[i] >> 24); out[4 * i + 1] = (CK_BYTE)(h[i] >> 16);
    out[4 * i + 2] = (CK_BYTE)(h[i] >> 8); out[4 * i + 3] = (CK_BYTE)h[i];
  }
}

/* Minimal DER walker: one TLV header plus constructed children. */
static int tlv_at(const CK_BYTE *tder, size_t len, size_t off, CK_BYTE *tag,
    size_t *voff, size_t *vlen) {
  if (off + 2 > len) return 0;
  CK_BYTE b1 = tder[off + 1];
  if (b1 < 0x80) {
    *tag = tder[off]; *voff = off + 2; *vlen = b1;
  } else {
    unsigned n = (unsigned)(b1 - 0x80);
    if (n < 1 || n > 4 || off + 2 + n > len) return 0;
    size_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = v * 256 + tder[off + 2 + i];
    *tag = tder[off]; *voff = off + 2 + n; *vlen = v;
  }
  return *voff + *vlen <= len;
}

static unsigned tbs_children(const CK_BYTE *tbs, size_t tbs_len, size_t off[10],
    size_t end[10]) {
  unsigned n = 0;
  size_t at = 0;
  while (at < tbs_len && n < 10) {
    CK_BYTE tag; size_t voff, vlen;
    if (!tlv_at(tbs, tbs_len, at, &tag, &voff, &vlen)) return 0;
    off[n] = at; end[n] = voff + vlen; ++n; at = voff + vlen;
  }
  return at == tbs_len ? n : 0;
}

/* Fixture bytes plus DER-derived search values (slices into der). */
static CK_BYTE der[4096];
static size_t der_len;
static const CK_BYTE *subj, *serial;
static size_t subj_len, serial_len;

static void load_fixture(void) {
  static const char pin_hex[] =
    "9b6838a4400677b3300d359834dcc53036f94cf04637c2d944ae1cfc75be3a23";
  FILE *f = fopen("tests/fixtures/cert-selfsigned.der", "rb");
  CK_BYTE sum[32];
  char hex[65];
  unsigned j;
  CK_BYTE tag;
  size_t voff, vlen, coff[10], cend[10], toff[10], tend[10];
  const CK_BYTE *tbs, *tv;
  size_t tbs_len, soff, svlen;
  if (!f) setup_error("fixture-unreadable");
  der_len = fread(der, 1, sizeof der, f);
  {
    int eos = feof(f);
    if (fclose(f) || !eos || der_len == 0 || der_len == sizeof der)
      setup_error("fixture-read");
  }
  sha256(der, der_len, sum);
  for (j = 0; j < 32; ++j) sprintf(hex + 2 * j, "%02x", sum[j]);
  if (strcmp(hex, pin_hex)) setup_error("fixture-sha-mismatch");
  if (!tlv_at(der, der_len, 0, &tag, &voff, &vlen) || tag != 0x30 ||
      voff + vlen != der_len)
    setup_error("fixture-outer");
  if (tbs_children(der + voff, vlen, coff, cend) < 1)
    setup_error("fixture-children");
  tbs = der + voff + coff[0];
  tbs_len = cend[0] - coff[0];
  if (!tlv_at(tbs, tbs_len, 0, &tag, &voff, &vlen) || tag != 0x30)
    setup_error("fixture-tbs");
  if (tbs_children(tbs + voff, vlen, toff, tend) < 7)
    setup_error("fixture-tbs-kids");
  tv = tbs + voff;
  if (!tlv_at(tv, vlen, toff[1], &tag, &soff, &svlen) || tag != 0x02)
    setup_error("fixture-serial");
  /* CKA_SERIAL_NUMBER carries the complete DER encoding (tag plus
   * length plus integer bytes), not the bare integer bytes. */
  serial = tv + toff[1];
  serial_len = tend[1] - toff[1];
  (void)soff;
  (void)svlen;
  if (!tlv_at(tv, vlen, toff[5], &tag, &soff, &svlen) || tag != 0x30)
    setup_error("fixture-subject");
  subj = tv + toff[5];
  subj_len = tend[5] - toff[5];
  printf("crypto: note: fixture bytes=%lu sha256=match subject=%lu serial=%lu\n",
         (unsigned long)der_len, (unsigned long)subj_len,
         (unsigned long)serial_len);
}

static char g_cfg_mem[512];
static char g_dir[64] = "/tmp/haskoki-certlink-XXXXXX";
static char g_cfg_sql[512];
static char g_db[512];

static void path_for(char *out, size_t size, const char *base) {
  int n = snprintf(out, size, "%s/%s", g_dir, base);
  if (n < 0 || (size_t)n >= size) setup_error("path-length");
}

static void make_dir(void) {
  if (!mkdtemp(g_dir)) setup_error("mkdtemp");
}

static void write_mem_config(void) {
  static const char body[] = "schema_version = 1\n"
                             "profile = \"real-crypto\"\n"
                             "[storage]\n"
                             "kind = \"memory\"\n"
                             "[engine]\n"
                             "kind = \"openssl\"\n"
                             "allow_synthetic_fallback = false\n"
                             "private_library_context = true\n"
                             "[trace]\n"
                             "enabled = false\n";
  char tmpl[] = "/tmp/haskoki-certlink-mem-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want;
  if (fd < 0) setup_error("mkstemp");
  want = sizeof(body) - 1;
  if (write(fd, body, want) != (ssize_t)want) setup_error("config-write");
  close(fd);
  snprintf(g_cfg_mem, sizeof(g_cfg_mem), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_mem, 1) != 0) setup_error("setenv");
}

static void write_sql_config(void) {
  FILE *f;
  path_for(g_cfg_sql, sizeof(g_cfg_sql), "certlink.toml");
  path_for(g_db, sizeof(g_db), "tokens.db");
  f = fopen(g_cfg_sql, "w");
  if (!f) setup_error("config-stream");
  if (fprintf(f,
              "schema_version = 1\nprofile = \"real-crypto\"\n"
              "[storage]\nkind = \"sqlite\"\npath = \"%s\"\n"
              "[engine]\nkind = \"openssl\"\n"
              "allow_synthetic_fallback = false\n"
              "private_library_context = true\n"
              "[trace]\nenabled = false\n",
              g_db) < 0)
    setup_error("config-write");
  if (fclose(f)) setup_error("config-close");
  if (setenv("HASKOKI_CONFIG", g_cfg_sql, 1) != 0) setup_error("setenv");
}

static CK_RV open_first(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE *out) {
  CK_SLOT_ID slots[8];
  CK_ULONG n = 8;
  CK_RV rv = f->C_GetSlotList(CK_FALSE, slots, &n);
  if (rv != CKR_OK || n < 1) return rv != CKR_OK ? rv : CKR_SLOT_ID_INVALID;
  return f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, out);
}

static CK_RV find_all(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE sess,
                      CK_ATTRIBUTE_PTR tmpl, CK_ULONG count,
                      CK_OBJECT_HANDLE *out, CK_ULONG cap, CK_ULONG *got) {
  CK_ULONG n = 0, chunk = 0;
  CK_RV rv = f->C_FindObjectsInit(sess, tmpl, count);
  CK_RV fin;
  if (rv != CKR_OK) return rv;
  for (;;) {
    rv = f->C_FindObjects(sess, out + n, cap - n, &chunk);
    if (rv != CKR_OK || chunk == 0) break;
    n += chunk;
    if (n >= cap) break;
  }
  fin = f->C_FindObjectsFinal(sess);
  if (rv == CKR_OK) rv = fin;
  *got = n;
  return rv;
}

static int has_handle(const CK_OBJECT_HANDLE *hs, CK_ULONG n,
                      CK_OBJECT_HANDLE h) {
  CK_ULONG k;
  for (k = 0; k < n; k++) {
    if (hs[k] == h) return 1;
  }
  return 0;
}

static const CK_BYTE kP256[] = {
  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
static const CK_BYTE kLinkId[] = { 0x01, 0x01 };
static const CK_BYTE kOtherId[] = { 0x02 };
static const CK_BYTE kAbsentId[] = { 0x09 };
static const char kLabel[] = "journey-cert";

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f = NULL_PTR;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE found[8];
  CK_ULONG nfound = 0;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  load_fixture();
  make_dir();
  write_mem_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL, "C_GetFunctionList resolves");
  rv = pGetList(&f);
  CHECK(rv == CKR_OK && f, "function list fetches");

  /* Interval one: memory store; link, readback, sign, negatives. */
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "memory C_Initialize ok");
  rv = open_first(f, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "memory session opens");
  rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECKC(rv == CKR_OK, "memory login ok");
  {
    CK_OBJECT_CLASS ccls = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE ctype = CKC_X_509;
    CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ekt = CKK_EC;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_OBJECT_HANDLE cert = 0, pub = 0, priv = 0, opub = 0, opriv = 0;
    CK_MECHANISM kgm, sm;
    CK_BYTE sig[256];
    CK_ULONG sigLen = 0;
    static const CK_BYTE msg[] = "certificate-linked application message";
    CK_ATTRIBUTE ctmpl[] = {
      { CKA_CLASS, &ccls, sizeof(ccls) },
      { CKA_CERTIFICATE_TYPE, &ctype, sizeof(ctype) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)kLabel, sizeof(kLabel) - 1 },
      { CKA_VALUE, der, der_len },
      { CKA_SUBJECT, (CK_VOID_PTR)subj, subj_len },
      { CKA_SERIAL_NUMBER, (CK_VOID_PTR)serial, serial_len }
    };
    CK_ATTRIBUTE pubT[] = {
      { CKA_CLASS, &pcls, sizeof(pcls) },
      { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
      { CKA_EC_PARAMS, (CK_VOID_PTR)kP256, sizeof(kP256) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) },
      { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_CLASS, &scls, sizeof(scls) },
      { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
    };
    rv = f->C_CreateObject(sess, ctmpl, 7, &cert);
    CHECKC(rv == CKR_OK && cert != 0, "certificate object mints");
    kgm.mechanism = CKM_EC_KEY_PAIR_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &kgm, pubT, 7, privT, 6, &pub, &priv);
    CHECKC(rv == CKR_OK && pub != 0 && priv != 0 && pub != priv,
           "linked pair mints");
    {
      CK_ATTRIBUTE set[] = {
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      rv = f->C_SetAttributeValue(sess, cert, set, 1);
      CHECKC(rv == CKR_OK, "certificate takes the link ID");
    }
    {
      CK_ATTRIBUTE q[] = {
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      CK_ATTRIBUTE qabs[] = {
        { CKA_ID, (CK_VOID_PTR)kAbsentId, sizeof(kAbsentId) }
      };
      rv = find_all(f, sess, q, 1, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 3, "find-by-ID returns three");
      CHECKC(has_handle(found, nfound, cert)
                 && has_handle(found, nfound, pub)
                 && has_handle(found, nfound, priv),
             "find-by-ID set holds certificate and pair");
      rv = find_all(f, sess, qabs, 1, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 0, "find-by-absent-ID returns none");
    }
    {
      CK_BYTE got[4096];
      CK_ATTRIBUTE rd[] = { { CKA_VALUE, got, sizeof(got) } };
      rv = f->C_GetAttributeValue(sess, cert, rd, 1);
      CHECKC(rv == CKR_OK && rd[0].ulValueLen == der_len &&
                 memcmp(got, der, der_len) == 0,
             "certificate VALUE reads back the DER");
    }
    {
      CK_BYTE got[512];
      CK_ATTRIBUTE rd[] = { { CKA_SUBJECT, got, sizeof(got) } };
      rv = f->C_GetAttributeValue(sess, cert, rd, 1);
      CHECKC(rv == CKR_OK && rd[0].ulValueLen == subj_len &&
                 memcmp(got, subj, subj_len) == 0,
             "certificate SUBJECT reads back");
    }
    {
      CK_BYTE one = 0xA5;
      CK_ATTRIBUTE rd[] = {
        { CKA_HASH_OF_CERTIFICATE, &one, sizeof(one) }
      };
      rv = f->C_GetAttributeValue(sess, cert, rd, 1);
      CHECKC(rv == CKR_ATTRIBUTE_TYPE_INVALID, "untyped hash refused");
      CHECKC(rd[0].ulValueLen == CK_UNAVAILABLE_INFORMATION,
             "refused attribute reports unavailable length");
      CHECKC(one == 0xA5, "refused attribute leaves the buffer untouched");
    }
    sm.mechanism = CKM_ECDSA_SHA256;
    sm.pParameter = NULL_PTR;
    sm.ulParameterLen = 0;
    rv = f->C_SignInit(sess, &sm, priv);
    CHECKC(rv == CKR_OK, "linked SignInit ok");
    sigLen = sizeof(sig);
    rv = f->C_Sign(sess, (CK_BYTE_PTR)msg, sizeof(msg) - 1, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen > 0 && sigLen <= sizeof(sig),
           "linked key signs the application message");
    rv = f->C_VerifyInit(sess, &sm, pub);
    CHECKC(rv == CKR_OK, "linked VerifyInit ok");
    rv = f->C_Verify(sess, (CK_BYTE_PTR)msg, sizeof(msg) - 1, sig, sigLen);
    CHECKC(rv == CKR_OK, "linked public key verifies");
    {
      CK_BYTE bad[64];
      memcpy(bad, msg, sizeof(msg) - 1);
      bad[0] ^= 0x01;
      rv = f->C_VerifyInit(sess, &sm, pub);
      CHECKC(rv == CKR_OK, "tamper VerifyInit ok");
      rv = f->C_Verify(sess, bad, sizeof(msg) - 1, sig, sigLen);
      CHECKC(rv == CKR_SIGNATURE_INVALID, "tampered message refused");
    }
    {
      CK_ATTRIBUTE opubT[] = {
        { CKA_CLASS, &pcls, sizeof(pcls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_EC_PARAMS, (CK_VOID_PTR)kP256, sizeof(kP256) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_ID, (CK_VOID_PTR)kOtherId, sizeof(kOtherId) }
      };
      CK_ATTRIBUTE oprivT[] = {
        { CKA_CLASS, &scls, sizeof(scls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_ID, (CK_VOID_PTR)kOtherId, sizeof(kOtherId) }
      };
      rv = f->C_GenerateKeyPair(sess, &kgm, opubT, 7, oprivT, 6,
                                &opub, &opriv);
      CHECKC(rv == CKR_OK && opub != 0 && opriv != 0,
             "distractor pair mints");
      rv = f->C_VerifyInit(sess, &sm, opub);
      CHECKC(rv == CKR_OK, "wrong-identity VerifyInit ok");
      rv = f->C_Verify(sess, (CK_BYTE_PTR)msg, sizeof(msg) - 1, sig, sigLen);
      CHECKC(rv == CKR_SIGNATURE_INVALID, "wrong identity refused");
      rv = f->C_DestroyObject(sess, opub);
      CHECKC(rv == CKR_OK, "distractor public destroys");
      rv = f->C_DestroyObject(sess, opriv);
      CHECKC(rv == CKR_OK, "distractor private destroys");
    }
    rv = f->C_DestroyObject(sess, cert);
    CHECKC(rv == CKR_OK, "session certificate destroys");
    rv = f->C_DestroyObject(sess, pub);
    CHECKC(rv == CKR_OK, "session public key destroys");
    rv = f->C_DestroyObject(sess, priv);
    CHECKC(rv == CKR_OK, "session private key destroys");
  }
  rv = f->C_Logout(sess);
  CHECKC(rv == CKR_OK, "memory logout ok");
  rv = f->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "memory session closes");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "memory C_Finalize ok");

  /* SQLite restart legs are direct-only: under proxy the
   * client cannot switch the daemon backend, and client
   * reattach is not a backend restart (same root cause as
   * the direct-only consumer_certificates:restart leg).
   * Skipped loudly in proxy mode, never silently. */
  if (!isProxy) {
    /* Interval two: SQLite store; persist the linked token objects.
     * Each C_Initialize opens a fresh instance from the current
     * HASKOKI_CONFIG, so pointing the environment at the SQLite
     * config before re-initializing switches stores in one process. */
    write_sql_config();
    rv = f->C_Initialize(NULL_PTR);
    CHECKC(rv == CKR_OK, "sqlite C_Initialize ok");
    rv = open_first(f, &sess);
    CHECKC(rv == CKR_OK && sess != 0, "sqlite session opens");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    CHECKC(rv == CKR_OK, "sqlite login ok");
    {
      CK_OBJECT_CLASS ccls = CKO_CERTIFICATE;
      CK_CERTIFICATE_TYPE ctype = CKC_X_509;
      CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY;
      CK_KEY_TYPE ekt = CKK_EC;
      CK_BBOOL bTrue = CK_TRUE;
      CK_OBJECT_HANDLE cert = 0, pub = 0, priv = 0;
      CK_MECHANISM kgm;
      CK_ATTRIBUTE ctmpl[] = {
        { CKA_CLASS, &ccls, sizeof(ccls) },
        { CKA_CERTIFICATE_TYPE, &ctype, sizeof(ctype) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)kLabel, sizeof(kLabel) - 1 },
        { CKA_VALUE, der, der_len },
        { CKA_SUBJECT, (CK_VOID_PTR)subj, subj_len },
        { CKA_SERIAL_NUMBER, (CK_VOID_PTR)serial, serial_len }
      };
      CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pcls, sizeof(pcls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_EC_PARAMS, (CK_VOID_PTR)kP256, sizeof(kP256) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &scls, sizeof(scls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      CK_ATTRIBUTE q[] = {
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      CK_ATTRIBUTE set[] = {
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      rv = f->C_CreateObject(sess, ctmpl, 7, &cert);
      CHECKC(rv == CKR_OK && cert != 0, "token certificate mints");
      kgm.mechanism = CKM_EC_KEY_PAIR_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(sess, &kgm, pubT, 6, privT, 6, &pub, &priv);
      CHECKC(rv == CKR_OK && pub != 0 && priv != 0 && pub != priv,
             "token pair mints");
      rv = f->C_SetAttributeValue(sess, cert, set, 1);
      CHECKC(rv == CKR_OK, "token certificate takes the link ID");
      rv = find_all(f, sess, q, 1, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 3, "token find-by-ID returns three");
      CHECKC(has_handle(found, nfound, cert)
                 && has_handle(found, nfound, pub)
                 && has_handle(found, nfound, priv),
             "token find-by-ID set holds certificate and pair");
    }
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "sqlite logout ok");
    rv = f->C_CloseSession(sess);
    CHECKC(rv == CKR_OK, "sqlite session closes");
    rv = f->C_Finalize(NULL_PTR);
    CHECKC(rv == CKR_OK, "sqlite C_Finalize ok");

    /* Interval three: reopen the same SQLite store; the linkage and
     * the bytes survive the restart, then destroy cleanly. */
    rv = f->C_Initialize(NULL_PTR);
    CHECKC(rv == CKR_OK, "reopen C_Initialize ok");
    rv = open_first(f, &sess);
    CHECKC(rv == CKR_OK && sess != 0, "reopen session opens");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    CHECKC(rv == CKR_OK, "reopen login ok");
    {
      CK_ATTRIBUTE q[] = {
        { CKA_ID, (CK_VOID_PTR)kLinkId, sizeof(kLinkId) }
      };
      CK_ULONG k;
      rv = find_all(f, sess, q, 1, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 3, "restart keeps the linkage");
      {
        CK_BYTE got[4096];
        CK_ULONG ci;
        int matched = 0;
        for (ci = 0; ci < nfound; ci++) {
          CK_OBJECT_CLASS cls = 0;
          CK_ATTRIBUTE qc[] = { { CKA_CLASS, &cls, sizeof(cls) } };
          CK_ATTRIBUTE rd[] = { { CKA_VALUE, got, sizeof(got) } };
          rv = f->C_GetAttributeValue(sess, found[ci], qc, 1);
          if (rv != CKR_OK || cls != CKO_CERTIFICATE) continue;
          rv = f->C_GetAttributeValue(sess, found[ci], rd, 1);
          if (rv == CKR_OK && rd[0].ulValueLen == der_len &&
              memcmp(got, der, der_len) == 0)
            matched = 1;
        }
        CHECKC(matched, "restart keeps the certificate bytes");
      }
      for (k = 0; k < nfound; k++) {
        rv = f->C_DestroyObject(sess, found[k]);
        CHECKC(rv == CKR_OK, "restarted object destroys");
      }
      rv = find_all(f, sess, q, 1, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 0, "destroyed linkage finds nothing");
    }
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "reopen logout ok");
    rv = f->C_CloseSession(sess);
    CHECKC(rv == CKR_OK, "reopen session closes");
    rv = f->C_Finalize(NULL_PTR);
    CHECKC(rv == CKR_OK, "reopen C_Finalize ok");
  } else {
    printf("crypto: note: sqlite restart legs are direct-only; "
           "skipped under proxy\n");
  }
  sess = 0;
  rv = f->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize OpenSession needs init");

  dlclose(handle);
  unlink(g_cfg_mem);
  unlink(g_cfg_sql);
  unlink(g_db);
  rmdir(g_dir);
  if (g_failures == 0) {
    printf("PASS: consumer_certlink (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}