/* Independent certificate contract, through each actual public table.
 * Build: cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor
 *   tests/c/consumer_certificates.c -ldl -lpthread -o consumer_certificates
 * No implementation headers, private entry points, or manufactured slot IDs.
 * T-C01..T-C07 own behavior; this T-C09 consumer independently consolidates it.
 * First-failure children are isolated; their parent still runs every matrix cell.
 * Every leg reads real DER from tests/fixtures/cert-selfsigned.der (SHA-256
 * pinned); no embedded synthetic cert bytes. Derived search values (subject,
 * issuer, serial, SPKI, hashes) come from parsing those loaded bytes.
 */
#define _GNU_SOURCE
#define CK_PTR *
#define CK_DECLARE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION_POINTER(r, n) r (*n)
#define CK_CALLBACK_FUNCTION(r, n) r (*n)
#include "pkcs11.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(CK_ULONG) == 8, "LP64 consumer");
#define SENTINEL 0xa5a5a5a5a5a5a5a5UL
#define N(a) (sizeof(a) / sizeof((a)[0]))
#define COMMON(F) F(Initialize) F(Finalize) F(GetInfo) F(GetSlotList) \
  F(GetSlotInfo) F(GetTokenInfo) F(GetMechanismList) F(GetMechanismInfo) \
  F(OpenSession) F(CloseSession) F(CloseAllSessions) F(GetSessionInfo) \
  F(Login) F(Logout) F(CreateObject) F(DestroyObject) F(CopyObject) \
  F(GetAttributeValue) F(SetAttributeValue) \
  F(FindObjectsInit) F(FindObjects) F(FindObjectsFinal)
#define FIELD(n) CK_C_##n n;
typedef struct { COMMON(FIELD) } Api;
#undef FIELD
/* Independent declaration of the sole vendor extension named here. */
typedef CK_RV (*Control)(const CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
static Api a;
static Control ctl;
static CK_C_GetFunctionList get_list;
static CK_C_GetInterface get_interface;
static CK_C_GetInterfaceList get_interfaces;
static const char *version, *storage, *leg, *directory;
static const char *versions[] = {"2.40", "3.0", "3.1", "3.2"};
static const char *stores[] = {"memory", "sqlite"};
static const char *legs[] = {"create", "find", "lifecycle", "visibility",
  "atomicity", "restart"};
static CK_SLOT_ID slots[2];
static unsigned slot_count;
static int live, failed;
static unsigned assertions;
static void *module;
static char fixture_config[PATH_MAX];
/* Fixture bytes: DER plus DER-derived search values (slices into der). */
static CK_BYTE der[4096];
static size_t der_len;
static CK_BYTE fixture_sha[32];
static const CK_BYTE *subj, *iss, *spki, *serial;
static size_t subj_len, iss_len, spki_len, serial_len;
static CK_BYTE hsubj[32], hiss[32];

/* All six assertion functions precede fixture implementations. Ownership
 * links name the recorded T-C01..T-C03 assertion cycles, not new reds. */
static int check(int, const char *);
static int expect(CK_RV, CK_RV, const char *);
static int filled(const void *, size_t);
static void setup_error(const char *);
static void sha256(const CK_BYTE *, size_t, CK_BYTE[32]);
static void load_fixture(void);
static void configure(int);
static void load_table(const char *, unsigned);
static void initialize(void);
static void finalize(void);
static void discover_slots(void);
static unsigned demo_slot(void);
static unsigned certb_slot(void);
static CK_SESSION_HANDLE session(unsigned, int);
static void login_user(CK_SESSION_HANDLE);
static void login_so(CK_SESSION_HANDLE);
static void logout(CK_SESSION_HANDLE);
static CK_OBJECT_HANDLE create_ok(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, const char *);
static void create_rv(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_RV, const char *);
static void read_exact(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_TYPE,
  const CK_BYTE *, CK_ULONG, const char *);
static void read_ulong(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_TYPE,
  CK_ULONG, const char *);
static void read_bool(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_TYPE,
  CK_BBOOL, const char *);
static void read_absent(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_TYPE,
  const char *);
static unsigned find_all(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG,
  CK_OBJECT_HANDLE *, unsigned);
static void find_contains(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG,
  CK_OBJECT_HANDLE, const char *);
static void find_count(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG,
  unsigned, const char *);
static void destroy(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, const char *);
static void cleanup(void);
#define REQUIRE(c, s) do { if (!check((c), (s))) return; } while (0)
#define RV(c, w, s) do { if (!expect((c), (w), (s))) return; } while (0)
#define STEP(c) do { c; if (failed) return; } while (0)

/* T-C01 caseCertRequiresTypeValueSubject/caseCertEmptySubjectAccepted;
 * T-C03 caseTrustedBoundary/caseCategoryRoundtrip/caseDateRoundtrip/
 * caseDateFormat. X.509 create gate plus trust/category/date admission. */
static void leg_create(void) {
  STEP(initialize());
  unsigned d = demo_slot();
  CK_SESSION_HANDLE h = session(d, 1); if (failed) return;
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509, cat1 = 1;
  CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
  CK_ATTRIBUTE full[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_LABEL, (CK_VOID_PTR)"create-full", 11},
  };
  CK_OBJECT_HANDLE o = create_ok(h, full, N(full), "create-full");
  if (failed) return;
  STEP(read_exact(h, o, CKA_VALUE, der, (CK_ULONG)der_len, "create-value-exact"));
  CK_ATTRIBUTE no_type[] = {full[0], full[2], full[3], full[4]};
  STEP(create_rv(h, no_type, N(no_type), CKR_TEMPLATE_INCOMPLETE, "missing-type"));
  CK_ATTRIBUTE no_value[] = {full[0], full[1], full[3], full[4]};
  STEP(create_rv(h, no_value, N(no_value), CKR_TEMPLATE_INCOMPLETE, "missing-value"));
  CK_ATTRIBUTE no_subject[] = {full[0], full[1], full[2], full[4]};
  STEP(create_rv(h, no_subject, N(no_subject), CKR_TEMPLATE_INCOMPLETE, "missing-subject"));
  CK_BYTE anchor = 0;
  CK_ATTRIBUTE empty_subj[] = {full[0], full[1], full[2], full[4],
    {CKA_SUBJECT, &anchor, 0}};
  if (!create_ok(h, empty_subj, N(empty_subj), "empty-subject")) return;
  CK_ATTRIBUTE trust_no[] = {full[0], full[1], full[2], full[3], full[4],
    {CKA_TRUSTED, &no, sizeof no}};
  CK_OBJECT_HANDLE t = create_ok(h, trust_no, N(trust_no), "trusted-false-create");
  if (failed) return;
  STEP(read_bool(h, t, CKA_TRUSTED, CK_FALSE, "trusted-false-readback"));
  STEP(login_user(h));
  CK_ATTRIBUTE trust_yes[] = {full[0], full[1], full[2], full[3], full[4],
    {CKA_TRUSTED, &yes, sizeof yes}};
  STEP(create_rv(h, trust_yes, N(trust_yes), CKR_ATTRIBUTE_READ_ONLY,
    "user-trusted-true-refused"));
  STEP(logout(h));
  STEP(login_so(h));
  CK_ATTRIBUTE so_trust[] = {full[0], full[1], full[2], full[3],
    {CKA_LABEL, (CK_VOID_PTR)"create-so", 9},
    {CKA_TRUSTED, &yes, sizeof yes}};
  CK_OBJECT_HANDLE s = create_ok(h, so_trust, N(so_trust), "so-trusted-true-create");
  if (failed) return;
  STEP(read_bool(h, s, CKA_TRUSTED, CK_TRUE, "so-trusted-true-readback"));
  STEP(logout(h));
  CK_ATTRIBUTE dated[] = {full[0], full[1], full[2], full[3],
    {CKA_LABEL, (CK_VOID_PTR)"create-dated", 12},
    {CKA_CERTIFICATE_CATEGORY, &cat1, sizeof cat1},
    {CKA_START_DATE, (CK_VOID_PTR)"20240131", 8},
    {CKA_END_DATE, (CK_VOID_PTR)"20250131", 8}};
  CK_OBJECT_HANDLE dc = create_ok(h, dated, N(dated), "category-date-create");
  if (failed) return;
  STEP(read_ulong(h, dc, CKA_CERTIFICATE_CATEGORY, 1, "category-readback"));
  STEP(read_exact(h, dc, CKA_START_DATE, (const CK_BYTE *)"20240131", 8, "start-date-readback"));
  STEP(read_exact(h, dc, CKA_END_DATE, (const CK_BYTE *)"20250131", 8, "end-date-readback"));
  static const struct { const char *bytes; CK_ATTRIBUTE_TYPE type; const char *name; } bad[] = {
    {"2024013", CKA_START_DATE, "bad-date-start-7"},
    {"202401311", CKA_START_DATE, "bad-date-start-9"},
    {"20240X31", CKA_START_DATE, "bad-date-start-nondigit"},
    {"2025013", CKA_END_DATE, "bad-date-end-7"},
    {"2025-01-3", CKA_END_DATE, "bad-date-end-nondigit"},
  };
  for (unsigned i = 0; i < N(bad); ++i) {
    CK_ATTRIBUTE tmpl[] = {full[0], full[1], full[2], full[3], full[4],
      {bad[i].type, (CK_VOID_PTR)bad[i].bytes, (CK_ULONG)strlen(bad[i].bytes)}};
    STEP(create_rv(h, tmpl, N(tmpl), CKR_TEMPLATE_INCONSISTENT, bad[i].name));
  }
  RV(a.CloseSession(h), CKR_OK, "create-close");
  STEP(finalize());
}

/* T-C03 caseTrustedBoundary (trusted find), caseCategoryRoundtrip and
 * caseDateRoundtrip (exact-value find); T-C04 caseSuppliedOpaque (find
 * by each supplied field). Equality search plus the real find cursor. */
static void leg_find(void) {
  STEP(initialize());
  unsigned d = demo_slot();
  CK_SESSION_HANDLE h = session(d, 1); if (failed) return;
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509, cat3 = 3;
  CK_BBOOL no = CK_FALSE;
  CK_ATTRIBUTE target[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_ISSUER, (CK_VOID_PTR)iss, (CK_ULONG)iss_len},
    {CKA_SERIAL_NUMBER, (CK_VOID_PTR)serial, (CK_ULONG)serial_len},
    {CKA_PUBLIC_KEY_INFO, (CK_VOID_PTR)spki, (CK_ULONG)spki_len},
    {CKA_HASH_OF_SUBJECT_PUBLIC_KEY, hsubj, sizeof hsubj},
    {CKA_HASH_OF_ISSUER_PUBLIC_KEY, hiss, sizeof hiss},
    {CKA_TRUSTED, &no, sizeof no},
    {CKA_CERTIFICATE_CATEGORY, &cat3, sizeof cat3},
    {CKA_START_DATE, (CK_VOID_PTR)"20240131", 8},
    {CKA_END_DATE, (CK_VOID_PTR)"20250131", 8},
    {CKA_LABEL, (CK_VOID_PTR)"find-target", 11},
  };
  CK_OBJECT_HANDLE o = create_ok(h, target, N(target), "find-import");
  if (failed) return;
  CK_ATTRIBUTE decoy[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)"decoy-subject", 13},
    {CKA_LABEL, (CK_VOID_PTR)"find-decoy", 10},
  };
  if (!create_ok(h, decoy, N(decoy), "find-decoy")) return;
  CK_ATTRIBUTE q_label[] = {{CKA_LABEL, (CK_VOID_PTR)"find-target", 11}};
  STEP(find_contains(h, q_label, N(q_label), o, "find-by-label"));
  CK_ATTRIBUTE q_subj[] = {target[0], target[3]};
  STEP(find_contains(h, q_subj, N(q_subj), o, "find-by-subject"));
  CK_ATTRIBUTE q_iss[] = {target[0], target[4]};
  STEP(find_contains(h, q_iss, N(q_iss), o, "find-by-issuer"));
  CK_ATTRIBUTE q_ser[] = {target[0], target[5]};
  STEP(find_contains(h, q_ser, N(q_ser), o, "find-by-serial"));
  CK_ATTRIBUTE q_subser[] = {target[0], target[3], target[5]};
  STEP(find_contains(h, q_subser, N(q_subser), o, "find-by-subject-serial"));
  CK_ATTRIBUTE q_trust[] = {target[0], target[9]};
  STEP(find_contains(h, q_trust, N(q_trust), o, "find-by-trusted"));
  CK_ATTRIBUTE q_cat[] = {target[0], target[10]};
  STEP(find_contains(h, q_cat, N(q_cat), o, "find-by-category"));
  CK_ATTRIBUTE q_start[] = {target[0], target[11]};
  STEP(find_contains(h, q_start, N(q_start), o, "find-by-start-date"));
  CK_ATTRIBUTE q_end[] = {target[0], target[12]};
  STEP(find_contains(h, q_end, N(q_end), o, "find-by-end-date"));
  CK_ATTRIBUTE q_hsubj[] = {target[0], target[7]};
  STEP(find_contains(h, q_hsubj, N(q_hsubj), o, "find-by-hash-subject"));
  CK_ATTRIBUTE q_hiss[] = {target[0], target[8]};
  STEP(find_contains(h, q_hiss, N(q_hiss), o, "find-by-hash-issuer"));
  CK_ATTRIBUTE q_spki[] = {target[0], target[6]};
  STEP(find_contains(h, q_spki, N(q_spki), o, "find-by-public-key-info"));
  CK_ATTRIBUTE q_wrong[] = {{CKA_LABEL, (CK_VOID_PTR)"find-absent", 11}};
  STEP(find_count(h, q_wrong, N(q_wrong), 0, "find-wrong-field-zero"));
  CK_ATTRIBUTE q_class[] = {target[0]};
  RV(a.FindObjectsInit(h, q_class, N(q_class)), CKR_OK, "cursor-init");
  RV(a.FindObjectsInit(h, q_class, N(q_class)), CKR_OPERATION_ACTIVE,
    "cursor-duplicate-init");
  CK_OBJECT_HANDLE page[2] = {SENTINEL, SENTINEL};
  CK_ULONG got = 0;
  RV(a.FindObjects(h, page, 1, &got), CKR_OK, "cursor-page-one");
  REQUIRE(got == 1 && page[0] != SENTINEL, "cursor-page-one-count");
  CK_OBJECT_HANDLE second = page[0];
  page[0] = SENTINEL; got = 0;
  RV(a.FindObjects(h, page, 1, &got), CKR_OK, "cursor-page-two");
  REQUIRE(got == 1 && page[0] != second && page[0] != SENTINEL, "cursor-page-two-distinct");
  REQUIRE(second == o || page[0] == o, "cursor-pages-cover-target");
  page[0] = SENTINEL; got = 7;
  RV(a.FindObjects(h, page, 1, &got), CKR_OK, "cursor-exhaustion");
  REQUIRE(got == 0 && page[0] == SENTINEL, "cursor-exhaustion-zero");
  RV(a.FindObjectsFinal(h), CKR_OK, "cursor-final");
  RV(a.FindObjectsFinal(h), CKR_OPERATION_NOT_INITIALIZED, "cursor-duplicate-final");
  CK_SESSION_HANDLE g = session(d, 1); if (failed) return;
  page[0] = SENTINEL; got = 7;
  RV(a.FindObjects(g, page, 1, &got), CKR_OPERATION_NOT_INITIALIZED, "cursor-find-no-init");
  REQUIRE(got == 7 && page[0] == SENTINEL, "cursor-no-init-canary");
  RV(a.CloseSession(g), CKR_OK, "find-close-second");
  RV(a.CloseSession(h), CKR_OK, "find-close");
  STEP(finalize());
}

/* T-C03 caseCertImmutableMatrix/caseCopyPrecedence/caseTrustedBoundary.
 * Copy/set mutability matrix plus destroy/double-destroy/read-after. */
static void leg_lifecycle(void) {
  STEP(initialize());
  unsigned d = demo_slot();
  CK_SESSION_HANDLE h = session(d, 1); if (failed) return;
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509, data = CKO_DATA;
  CK_ULONG t1 = 1, cat9 = 9;
  CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
  CK_ATTRIBUTE src[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_LABEL, (CK_VOID_PTR)"lifecycle-src", 13},
  };
  CK_OBJECT_HANDLE o = create_ok(h, src, N(src), "lifecycle-import");
  if (failed) return;
  CK_ATTRIBUTE lbl[] = {{CKA_LABEL, (CK_VOID_PTR)"lifecycle-copy", 14}};
  CK_OBJECT_HANDLE c = SENTINEL;
  RV(a.CopyObject(h, o, lbl, N(lbl), &c), CKR_OK, "copy-label-override");
  REQUIRE(c != 0 && c != SENTINEL && c != o, "copy-distinct-handle");
  STEP(read_ulong(h, c, CKA_CLASS, CKO_CERTIFICATE, "copy-inherited-class"));
  STEP(read_exact(h, c, CKA_LABEL, (const CK_BYTE *)"lifecycle-copy", 14,
    "copy-label-stored"));
  STEP(read_exact(h, c, CKA_VALUE, der, (CK_ULONG)der_len, "copy-value-inherited"));
  CK_ATTRIBUTE cover[] = {
    {CKA_CLASS, &data, sizeof data},
    {CKA_CERTIFICATE_TYPE, &t1, sizeof t1},
    {CKA_VALUE, (CK_VOID_PTR)"other", 5},
    {CKA_SUBJECT, (CK_VOID_PTR)"other-subject", 13},
    {CKA_ISSUER, (CK_VOID_PTR)"other-issuer", 12},
    {CKA_SERIAL_NUMBER, (CK_VOID_PTR)"other-serial", 12},
    {CKA_PUBLIC_KEY_INFO, (CK_VOID_PTR)"other-pki", 9},
    {CKA_HASH_OF_SUBJECT_PUBLIC_KEY, (CK_VOID_PTR)"other-h1", 8},
    {CKA_HASH_OF_ISSUER_PUBLIC_KEY, (CK_VOID_PTR)"other-h2", 8},
    {CKA_TRUSTED, &yes, sizeof yes},
    {CKA_CERTIFICATE_CATEGORY, &cat9, sizeof cat9},
    {CKA_START_DATE, (CK_VOID_PTR)"20250101", 8},
    {CKA_END_DATE, (CK_VOID_PTR)"20260101", 8},
  };
  static const char *cnames[] = {"copy-refuse-class", "copy-refuse-type",
    "copy-refuse-value", "copy-refuse-subject", "copy-refuse-issuer",
    "copy-refuse-serial", "copy-refuse-public-key-info",
    "copy-refuse-hash-subject", "copy-refuse-hash-issuer",
    "copy-refuse-trusted", "copy-refuse-category",
    "copy-refuse-start-date", "copy-refuse-end-date"};
  for (unsigned i = 0; i < N(cover); ++i) {
    CK_OBJECT_HANDLE n = SENTINEL;
    RV(a.CopyObject(h, o, &cover[i], 1, &n), CKR_TEMPLATE_INCONSISTENT, cnames[i]);
    REQUIRE(n == SENTINEL, "copy-refuse-canary");
  }
  static const char *snames[] = {"set-refuse-class", "set-refuse-type",
    "set-refuse-value", "set-refuse-subject", "set-refuse-issuer",
    "set-refuse-serial", "set-refuse-public-key-info",
    "set-refuse-hash-subject", "set-refuse-hash-issuer",
    "set-refuse-category", "set-refuse-start-date", "set-refuse-end-date"};
  for (unsigned i = 0; i < N(cover); ++i) {
    if (cover[i].type == CKA_TRUSTED) continue;
    RV(a.SetAttributeValue(h, o, &cover[i], 1), CKR_ATTRIBUTE_READ_ONLY,
      snames[i < 9 ? i : i - 1]);
    STEP(read_exact(h, o, CKA_LABEL, (const CK_BYTE *)"lifecycle-src", 13,
      "set-refuse-label-intact"));
  }
  CK_ATTRIBUTE tset[] = {{CKA_TRUSTED, &yes, sizeof yes}};
  RV(a.SetAttributeValue(h, o, tset, N(tset)), CKR_ATTRIBUTE_READ_ONLY,
    "set-trusted-true-public-refused");
  CK_ATTRIBUTE newlbl[] = {{CKA_LABEL, (CK_VOID_PTR)"lifecycle-set", 13}};
  RV(a.SetAttributeValue(h, o, newlbl, N(newlbl)), CKR_OK, "set-label");
  STEP(read_exact(h, o, CKA_LABEL, (const CK_BYTE *)"lifecycle-set", 13,
    "set-label-readback"));
  CK_ATTRIBUTE newid[] = {{CKA_ID, (CK_VOID_PTR)"lifecycle-id", 12}};
  RV(a.SetAttributeValue(h, o, newid, N(newid)), CKR_OK, "set-id");
  STEP(read_exact(h, o, CKA_ID, (const CK_BYTE *)"lifecycle-id", 12, "set-id-readback"));
  CK_ATTRIBUTE tno[] = {{CKA_TRUSTED, &no, sizeof no}};
  RV(a.SetAttributeValue(h, o, tno, N(tno)), CKR_OK, "set-trusted-false-public");
  STEP(read_bool(h, o, CKA_TRUSTED, CK_FALSE, "trusted-false-set-readback"));
  STEP(login_user(h));
  RV(a.SetAttributeValue(h, o, tno, N(tno)), CKR_OK, "set-trusted-false-user");
  RV(a.SetAttributeValue(h, o, tset, N(tset)), CKR_ATTRIBUTE_READ_ONLY,
    "set-trusted-true-user-refused");
  STEP(logout(h));
  STEP(login_so(h));
  RV(a.SetAttributeValue(h, o, tset, N(tset)), CKR_OK, "set-trusted-true-so");
  STEP(read_bool(h, o, CKA_TRUSTED, CK_TRUE, "trusted-true-so-readback"));
  CK_OBJECT_HANDLE n = SENTINEL;
  RV(a.CopyObject(h, o, tset, N(tset), &n), CKR_TEMPLATE_INCONSISTENT,
    "copy-trusted-true-so-refused");
  REQUIRE(n == SENTINEL, "copy-so-refuse-canary");
  STEP(logout(h));
  STEP(destroy(h, o, "destroy"));
  RV(a.DestroyObject(h, o), CKR_OBJECT_HANDLE_INVALID, "destroy-double");
  CK_BYTE buf[64]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{CKA_LABEL, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OBJECT_HANDLE_INVALID,
    "read-after-destroy");
  REQUIRE(filled(buf, sizeof buf) && get[0].ulValueLen == sizeof buf,
    "read-after-destroy-canary");
  RV(a.CloseSession(h), CKR_OK, "lifecycle-close");
  STEP(finalize());
}

/* T-C01 create gate plus the session/token admission rules: private
 * visibility needs login, objects stay on their slot, read-only
 * sessions cannot mint token objects but read and find them. */
static void leg_visibility(void) {
  STEP(initialize());
  unsigned ia = demo_slot(), ib = certb_slot();
  REQUIRE(ia != ib, "visibility-two-tokens");
  CK_SESSION_HANDLE h = session(ia, 1); if (failed) return;
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509;
  CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
  CK_ATTRIBUTE priv[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_TOKEN, &yes, sizeof yes},
    {CKA_PRIVATE, &yes, sizeof yes},
    {CKA_LABEL, (CK_VOID_PTR)"vis-private", 11},
  };
  STEP(create_rv(h, priv, N(priv), CKR_USER_NOT_LOGGED_IN,
    "visibility-public-create-private-refused"));
  STEP(login_user(h));
  CK_OBJECT_HANDLE o = create_ok(h, priv, N(priv), "visibility-private-create");
  if (failed) return;
  CK_SESSION_HANDLE g = session(ia, 1); if (failed) return;
  CK_ATTRIBUTE q[] = {{CKA_LABEL, (CK_VOID_PTR)"vis-private", 11}};
  STEP(find_count(g, q, N(q), 1, "visibility-cross-session-immediate"));
  STEP(logout(h));
  STEP(find_count(g, q, N(q), 0, "visibility-public-invisible"));
  CK_BYTE buf[64]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{CKA_LABEL, buf, sizeof buf}};
  RV(a.GetAttributeValue(g, o, get, N(get)), CKR_OBJECT_HANDLE_INVALID,
    "visibility-public-read-invalid");
  REQUIRE(filled(buf, sizeof buf) && get[0].ulValueLen == sizeof buf,
    "visibility-public-read-canary");
  STEP(login_user(g));
  CK_OBJECT_HANDLE fresh[2] = {SENTINEL, SENTINEL};
  unsigned nfound = find_all(g, q, N(q), fresh, N(fresh));
  REQUIRE(nfound == 1 && fresh[0] != SENTINEL, "visibility-login-visible");
  /* Logout stales pre-logout private bindings (planLogout bumps them);
   * post-login discovery mints the fresh handle used from here on. */
  REQUIRE(fresh[0] != o, "visibility-login-fresh-handle");
  STEP(read_exact(g, fresh[0], CKA_VALUE, der, (CK_ULONG)der_len,
    "visibility-login-value-exact"));
  CK_SESSION_HANDLE other = session(ib, 1); if (failed) return;
  STEP(find_count(other, q, N(q), 0, "visibility-cross-slot-invisible"));
  CK_ATTRIBUTE pub[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_TOKEN, &yes, sizeof yes},
    {CKA_PRIVATE, &no, sizeof no},
    {CKA_LABEL, (CK_VOID_PTR)"vis-public-a", 12},
  };
  CK_OBJECT_HANDLE p = create_ok(h, pub, N(pub), "visibility-public-create");
  if (failed) return;
  CK_ATTRIBUTE qp[] = {{CKA_LABEL, (CK_VOID_PTR)"vis-public-a", 12}};
  STEP(find_count(h, qp, N(qp), 1, "visibility-same-slot-public"));
  STEP(find_count(other, qp, N(qp), 0, "visibility-cross-slot-public-invisible"));
  CK_SESSION_HANDLE ro = session(ia, 0); if (failed) return;
  CK_ATTRIBUTE tok[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_TOKEN, &yes, sizeof yes},
    {CKA_LABEL, (CK_VOID_PTR)"vis-ro-token", 12},
  };
  STEP(create_rv(ro, tok, N(tok), CKR_SESSION_READ_ONLY,
    "visibility-readonly-create-refused"));
  STEP(find_count(ro, qp, N(qp), 1, "visibility-readonly-find"));
  STEP(read_exact(ro, p, CKA_VALUE, der, (CK_ULONG)der_len,
    "visibility-readonly-read-exact"));
  RV(a.CloseSession(ro), CKR_OK, "visibility-close-ro");
  RV(a.CloseSession(other), CKR_OK, "visibility-close-other");
  RV(a.CloseSession(g), CKR_OK, "visibility-close-second");
  RV(a.CloseSession(h), CKR_OK, "visibility-close");
  STEP(finalize());
}

/* T-C03 caseTrustedAtomicity/caseCertPrecedenceTyped. Refused writes
 * are all-or-nothing and refusal paths leave outputs untouched. */
static void leg_atomicity(void) {
  STEP(initialize());
  unsigned d = demo_slot();
  CK_SESSION_HANDLE h = session(d, 1); if (failed) return;
  STEP(login_user(h));
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509;
  CK_BBOOL yes = CK_TRUE;
  CK_ATTRIBUTE tmpl[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_LABEL, (CK_VOID_PTR)"atom", 4},
  };
  CK_OBJECT_HANDLE o = create_ok(h, tmpl, N(tmpl), "atomicity-import");
  if (failed) return;
  CK_ATTRIBUTE mixed[] = {
    {CKA_LABEL, (CK_VOID_PTR)"moved", 5},
    {CKA_TRUSTED, &yes, sizeof yes},
  };
  RV(a.SetAttributeValue(h, o, mixed, N(mixed)), CKR_ATTRIBUTE_READ_ONLY,
    "atomicity-mixed-set-refused");
  STEP(read_exact(h, o, CKA_LABEL, (const CK_BYTE *)"atom", 4,
    "atomicity-label-intact"));
  STEP(read_absent(h, o, CKA_TRUSTED, "atomicity-trusted-intact"));
  CK_ATTRIBUTE contra[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_LABEL, (CK_VOID_PTR)"doomed-a", 8},
    {CKA_LABEL, (CK_VOID_PTR)"doomed-b", 8},
  };
  STEP(create_rv(h, contra, N(contra), CKR_TEMPLATE_INCONSISTENT,
    "atomicity-contradictory-create-refused"));
  CK_ATTRIBUTE qa[] = {{CKA_LABEL, (CK_VOID_PTR)"doomed-a", 8}};
  STEP(find_count(h, qa, N(qa), 0, "atomicity-no-object-a"));
  CK_ATTRIBUTE qb[] = {{CKA_LABEL, (CK_VOID_PTR)"doomed-b", 8}};
  STEP(find_count(h, qb, N(qb), 0, "atomicity-no-object-b"));
  STEP(find_count(h, NULL, 0, 1, "atomicity-singleton-census"));
  CK_ATTRIBUTE cover[] = {{CKA_VALUE, (CK_VOID_PTR)"other", 5}};
  CK_OBJECT_HANDLE n = SENTINEL;
  RV(a.CopyObject(h, o, cover, N(cover), &n), CKR_TEMPLATE_INCONSISTENT,
    "atomicity-refused-copy");
  REQUIRE(n == SENTINEL, "atomicity-copy-canary");
  STEP(destroy(h, o, "atomicity-destroy"));
  CK_BYTE buf[128]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{CKA_VALUE, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OBJECT_HANDLE_INVALID,
    "atomicity-read-after-destroy");
  REQUIRE(filled(buf, sizeof buf) && get[0].ulValueLen == sizeof buf,
    "atomicity-buffer-canary");
  RV(a.CloseSession(h), CKR_OK, "atomicity-close");
  STEP(finalize());
}

/* T-C02 caseCertTokenRestart/caseCertSessionVolatile. Token certs
 * survive a SQLite restart with exact readback and fresh handles;
 * session certs never survive; memory stays volatile. */
static void leg_restart(void) {
  STEP(initialize());
  unsigned d = demo_slot();
  CK_SESSION_HANDLE h = session(d, 1); if (failed) return;
  CK_ULONG klass = CKO_CERTIFICATE, x509 = CKC_X_509;
  CK_BBOOL yes = CK_TRUE;
  CK_ATTRIBUTE tok[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_TOKEN, &yes, sizeof yes},
    {CKA_LABEL, (CK_VOID_PTR)"restart-token", 13},
  };
  CK_OBJECT_HANDLE o = create_ok(h, tok, N(tok), "restart-token-create");
  if (failed) return;
  CK_ATTRIBUTE ses[] = {
    {CKA_CLASS, &klass, sizeof klass},
    {CKA_CERTIFICATE_TYPE, &x509, sizeof x509},
    {CKA_VALUE, der, (CK_ULONG)der_len},
    {CKA_SUBJECT, (CK_VOID_PTR)subj, (CK_ULONG)subj_len},
    {CKA_LABEL, (CK_VOID_PTR)"restart-session", 15},
  };
  if (!create_ok(h, ses, N(ses), "restart-session-create")) return;
  STEP(finalize());
  STEP(initialize());
  d = demo_slot();
  h = session(d, 1); if (failed) return;
  CK_ATTRIBUTE qt[] = {{CKA_LABEL, (CK_VOID_PTR)"restart-token", 13}};
  CK_ATTRIBUTE qs[] = {{CKA_LABEL, (CK_VOID_PTR)"restart-session", 15}};
  if (!strcmp(storage, "sqlite")) {
    CK_OBJECT_HANDLE fresh[2] = {SENTINEL, SENTINEL};
    unsigned found = find_all(h, qt, N(qt), fresh, N(fresh));
    REQUIRE(found == 1 && fresh[0] != SENTINEL, "restart-token-refind");
    STEP(read_exact(h, fresh[0], CKA_VALUE, der, (CK_ULONG)der_len,
      "restart-value-readback"));
    STEP(read_exact(h, fresh[0], CKA_SUBJECT, subj, (CK_ULONG)subj_len,
      "restart-subject-readback"));
    STEP(find_count(h, qs, N(qs), 0, "restart-session-gone"));
    CK_BYTE buf[64]; memset(buf, 0xa5, sizeof buf);
    CK_ATTRIBUTE get[] = {{CKA_VALUE, buf, sizeof buf}};
    RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OBJECT_HANDLE_INVALID,
      "restart-stale-fault");
    REQUIRE(filled(buf, sizeof buf) && get[0].ulValueLen == sizeof buf,
      "restart-stale-canary");
  } else {
    STEP(find_count(h, qt, N(qt), 0, "restart-memory-volatile"));
    STEP(find_count(h, qs, N(qs), 0, "restart-memory-session-gone"));
    CK_BYTE buf[64]; memset(buf, 0xa5, sizeof buf);
    CK_ATTRIBUTE get[] = {{CKA_VALUE, buf, sizeof buf}};
    RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OBJECT_HANDLE_INVALID,
      "restart-memory-stale-fault");
  }
  RV(a.CloseSession(h), CKR_OK, "restart-close");
  STEP(finalize());
}

/* Fixture implementations are added only after the six assertion bodies. */
static int check(int good, const char *name) {
  if (failed) return 0;
  ++assertions;
  printf("certificates:%s/%s/%s/%s check=%s\n", leg, name, version, storage,
    good ? "pass" : "FAIL");
  if (!good) failed = 1;
  return good;
}
static int expect(CK_RV got, CK_RV want, const char *name) {
  if (failed) return 0;
  printf("certificates:%s/%s/%s/%s rv=0x%lx expected=0x%lx\n", leg, name,
    version, storage, (unsigned long)got, (unsigned long)want);
  return check(got == want, name);
}
static int filled(const void *memory, size_t n) {
  const CK_BYTE *p = memory;
  for (size_t i = 0; i < n; ++i) if (p[i] != 0xa5) return 0;
  return 1;
}
static void setup_error(const char *what) {
  printf("certificates:%s/setup-error/%s/%s reason=%s\n", leg, version, storage, what);
  printf("CERT-RESULT: SETUP-FAIL version=%s storage=%s leg=%s\n", version, storage, leg);
  /* Process exit, never a semantic-red relabel. Parent reaps this child. */
  _Exit(2);
}
/* Compact SHA-256 (FIPS 180-4) for the fixture pin and digest status. */
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
/* Minimal DER walker (mirrors the T-C02 derSubject shape, extended to
 * serial/issuer/SPKI): one TLV header plus constructed children. */
static int tlv_at(const CK_BYTE *der, size_t len, size_t off, CK_BYTE *tag,
    size_t *voff, size_t *vlen) {
  if (off + 2 > len) return 0;
  CK_BYTE b1 = der[off + 1];
  if (b1 < 0x80) {
    *tag = der[off]; *voff = off + 2; *vlen = b1;
  } else {
    unsigned n = (unsigned)(b1 - 0x80);
    if (n < 1 || n > 4 || off + 2 + n > len) return 0;
    size_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = v * 256 + der[off + 2 + i];
    *tag = der[off]; *voff = off + 2 + n; *vlen = v;
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
static void load_fixture(void) {
  static const char pin_hex[] =
    "9b6838a4400677b3300d359834dcc53036f94cf04637c2d944ae1cfc75be3a23";
  FILE *f = fopen("tests/fixtures/cert-selfsigned.der", "rb");
  if (!f) setup_error("fixture-unreadable");
  der_len = fread(der, 1, sizeof der, f);
  int eos = feof(f);
  if (fclose(f) || !eos || der_len == 0 || der_len == sizeof der)
    setup_error("fixture-read");
  sha256(der, der_len, fixture_sha);
  char hex[65];
  for (unsigned i = 0; i < 32; ++i) sprintf(hex + 2 * i, "%02x", fixture_sha[i]);
  if (strcmp(hex, pin_hex)) setup_error("fixture-sha-mismatch");
  CK_BYTE tag; size_t voff, vlen;
  if (!tlv_at(der, der_len, 0, &tag, &voff, &vlen) || tag != 0x30 ||
      voff + vlen != der_len)
    setup_error("fixture-outer");
  size_t coff[10], cend[10];
  unsigned nkids = tbs_children(der + voff, vlen, coff, cend);
  if (nkids < 1) setup_error("fixture-children");
  const CK_BYTE *tbs = der + voff + coff[0];
  size_t tbs_len = cend[0] - coff[0];
  if (!tlv_at(tbs, tbs_len, 0, &tag, &voff, &vlen) || tag != 0x30)
    setup_error("fixture-tbs");
  size_t toff[10], tend[10];
  if (tbs_children(tbs + voff, vlen, toff, tend) < 7) setup_error("fixture-tbs-kids");
  const CK_BYTE *tv = tbs + voff;
  size_t soff, svlen, iooff, iovlen, qoff, qvlen;
  if (!tlv_at(tv, vlen, toff[1], &tag, &soff, &svlen) || tag != 0x02)
    setup_error("fixture-serial");
  serial = tv + soff; serial_len = svlen;
  if (!tlv_at(tv, vlen, toff[3], &tag, &iooff, &iovlen) || tag != 0x30)
    setup_error("fixture-issuer");
  iss = tv + toff[3]; iss_len = tend[3] - toff[3];
  (void)iooff; (void)iovlen;
  if (!tlv_at(tv, vlen, toff[5], &tag, &soff, &svlen) || tag != 0x30)
    setup_error("fixture-subject");
  subj = tv + toff[5]; subj_len = tend[5] - toff[5];
  if (!tlv_at(tv, vlen, toff[6], &tag, &qoff, &qvlen) || tag != 0x30)
    setup_error("fixture-spki");
  spki = tv + toff[6]; spki_len = tend[6] - toff[6];
  /* Opaque supplied hashes derived from the real SPKI bytes; the
   * fixture is self-signed, so issuer and subject share the key. */
  sha256(spki, spki_len, hsubj);
  memcpy(hiss, hsubj, sizeof hiss);
  printf("certificates:%s/fixture/%s/%s bytes=%lu sha256=match "
    "subject=%lu issuer=%lu serial=%lu spki=%lu\n", leg, version, storage,
    (unsigned long)der_len, (unsigned long)subj_len, (unsigned long)iss_len,
    (unsigned long)serial_len, (unsigned long)spki_len);
}
static void path_for(char *out, size_t size, const char *base) {
  int n = snprintf(out, size, "%s/%s", directory, base);
  if (n < 0 || (size_t)n >= size) setup_error("path-length");
}
/* Mirrors the notifications_routed.c configure() writer (verified span
 * 502-522): one token for five legs, two labeled tokens for visibility. */
static void configure(int two_tokens) {
  path_for(fixture_config, sizeof(fixture_config), "cert.toml");
  int fd = open(fixture_config, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
  if (fd < 0) {
    if (errno != EEXIST) setup_error("config-create");
    /* Within one owned child only: re-init reuses this config. */
  } else {
    FILE *f = fdopen(fd, "w"); if (!f) setup_error("config-stream");
    int wrote = fprintf(f, "schema_version = 1\nprofile = \"real-crypto\"\n"
      "[tokens]\nlabels = [%s]\n"
      "so_pins = [%s]\nuser_pins = [%s]\n"
      "[storage]\nkind = \"%s\"\n",
      two_tokens ? "\"haskoki-demo\", \"certificates-B\"" : "\"haskoki-demo\"",
      two_tokens ? "\"5678\", \"5678\"" : "\"5678\"",
      two_tokens ? "\"1234\", \"1234\"" : "\"1234\"", storage);
    if (!strcmp(storage, "sqlite") && fprintf(f, "path = \"%s/tokens.db\"\n", directory) < 0)
      setup_error("sqlite-config");
    int rest = fprintf(f, "[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\n"
      "private_library_context = true\n[trace]\nenabled = false\n");
    if (fclose(f) || wrote < 0 || rest < 0) setup_error("config-write");
  }
  if (setenv("HASKOKI_CONFIG", fixture_config, 1)) setup_error("config-environment");
}
static void load_table(const char *path, unsigned index) {
  module = dlopen(path, RTLD_NOW | RTLD_LOCAL); if (!module) setup_error("module-load");
  get_list = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
  get_interface = (CK_C_GetInterface)dlsym(module, "C_GetInterface");
  get_interfaces = (CK_C_GetInterfaceList)dlsym(module, "C_GetInterfaceList");
  ctl = (Control)dlsym(module, "HASKOKI_Control");
  if (!get_list || !get_interface || !get_interfaces) setup_error("discovery-symbols");
  (void)ctl;
#define COPY(n) a.n = table->C_##n;
  if (index == 0) {
    CK_FUNCTION_LIST *table = NULL;
    RV(get_list(&table), CKR_OK, "legacy-discovery"); REQUIRE(table != NULL, "legacy-table");
    REQUIRE(table->version.major == 2 && table->version.minor == 40, "legacy-version");
    COMMON(COPY)
  } else {
    CK_VERSION want = {3, (CK_BYTE)(index - 1)}, actual;
    CK_INTERFACE *interface = NULL;
    RV(get_interface(NULL, &want, &interface, 0), CKR_OK, "requested-discovery");
    REQUIRE(interface && interface->pFunctionList, "requested-table");
    memcpy(&actual, interface->pFunctionList, sizeof(actual));
    REQUIRE(actual.major == want.major && actual.minor == want.minor, "requested-version");
    if (index < 3) {
      CK_FUNCTION_LIST_3_0 *table = interface->pFunctionList;
      COMMON(COPY)
    } else {
      CK_FUNCTION_LIST_3_2 *table = interface->pFunctionList;
      COMMON(COPY)
    }
  }
#undef COPY
#define NONNULL(n) REQUIRE(a.n != NULL, "member-" #n);
  COMMON(NONNULL)
#undef NONNULL
}
static void initialize(void) {
  CK_C_INITIALIZE_ARGS args = {0}; args.flags = CKF_OS_LOCKING_OK;
  RV(a.Initialize(&args), CKR_OK, "initialize"); live = 1;
  STEP(discover_slots());
}
static void finalize(void) {
  RV(a.Finalize(NULL), CKR_OK, "finalize"); live = 0;
}
/* Enumerate every configured slot and map token labels to logical
 * roles. Discovery details stay on topology: lines (excluded from
 * parity transcripts); only role presence gates the legs, so one-
 * and two-token catalogs run identical assertion sequences. */
static unsigned demo_index, certb_index;
static int demo_present, certb_present;
static void discover_slots(void) {
  CK_ULONG count = 0;
  if (a.GetSlotList(CK_FALSE, NULL, &count) != CKR_OK) setup_error("discover-count");
  if (count < 1 || count > 2) setup_error("discover-count-range");
  CK_ULONG got = count;
  if (a.GetSlotList(CK_FALSE, slots, &got) != CKR_OK || got != count)
    setup_error("discover-list");
  slot_count = (unsigned)count;
  demo_present = 0; certb_present = 0;
  for (unsigned i = 0; i < slot_count; ++i) {
    CK_TOKEN_INFO info;
    if (a.GetTokenInfo(slots[i], &info) != CKR_OK) setup_error("discover-token-info");
    char label[33]; memcpy(label, info.label, 32); label[32] = 0;
    for (int k = 31; k >= 0 && label[k] == ' '; --k) label[k] = 0;
    if (!strcmp(label, "haskoki-demo")) { demo_index = i; demo_present = 1; }
    if (!strcmp(label, "certificates-B")) { certb_index = i; certb_present = 1; }
  }
  printf("topology: certificates discovered count=%u demo=%s certs-b=%s\n",
    slot_count, demo_present ? "present" : "absent", certb_present ? "present" : "absent");
}
static unsigned demo_slot(void) {
  if (!demo_present) setup_error("demo-slot-absent");
  return demo_index;
}
static unsigned certb_slot(void) {
  if (!certb_present) setup_error("certb-slot-absent");
  return certb_index;
}
static CK_SESSION_HANDLE session(unsigned i, int rw) {
  CK_SESSION_HANDLE h = SENTINEL;
  if (!expect(a.OpenSession(slots[i], CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0),
      NULL, NULL, &h), CKR_OK, "session-open")) return SENTINEL;
  check(h != SENTINEL && h != CK_INVALID_HANDLE, "session-published"); return h;
}
static void login_user(CK_SESSION_HANDLE h) {
  RV(a.Login(h, CKU_USER, (CK_UTF8CHAR *)"1234", 4), CKR_OK, "login-user");
}
static void login_so(CK_SESSION_HANDLE h) {
  RV(a.Login(h, CKU_SO, (CK_UTF8CHAR *)"5678", 4), CKR_OK, "login-so");
}
static void logout(CK_SESSION_HANDLE h) {
  RV(a.Logout(h), CKR_OK, "logout");
}
static void print_digest(const char *name, const CK_BYTE *bytes, CK_ULONG n, int match) {
  CK_BYTE sum[32];
  sha256(bytes, (size_t)n, sum);
  printf("certificates:%s/%s/%s/%s length=%lu digest=", leg, name, version,
    storage, (unsigned long)n);
  for (unsigned i = 0; i < 32; ++i) printf("%02x", sum[i]);
  printf(" status=%s\n", match ? "match" : "MISMATCH");
}
static CK_OBJECT_HANDLE create_ok(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl,
    CK_ULONG n, const char *name) {
  CK_OBJECT_HANDLE o = SENTINEL;
  if (!expect(a.CreateObject(h, tmpl, n, &o), CKR_OK, name)) return 0;
  if (!check(o != 0 && o != SENTINEL, name)) return 0;
  return o;
}
static void create_rv(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG n,
    CK_RV want, const char *name) {
  CK_OBJECT_HANDLE o = SENTINEL;
  RV(a.CreateObject(h, tmpl, n, &o), want, name);
  REQUIRE(o == SENTINEL, name);
}
static void read_exact(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE type, const CK_BYTE *want, CK_ULONG n, const char *name) {
  static CK_BYTE buf[4096];
  if ((size_t)n > sizeof buf) setup_error("read-too-large");
  memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{type, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OK, name);
  if (get[0].ulValueLen > sizeof buf) {
    printf("certificates:%s/%s/%s/%s length=%lu status=MALFORMED-LENGTH\n",
      leg, name, version, storage, (unsigned long)get[0].ulValueLen);
    REQUIRE(0, name);
  }
  int same = get[0].ulValueLen == n && !memcmp(buf, want, (size_t)n) &&
    filled(buf + (size_t)n, sizeof buf - (size_t)n);
  print_digest(name, buf, get[0].ulValueLen, same && get[0].ulValueLen == n);
  REQUIRE(same, name);
}
static void read_ulong(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE type, CK_ULONG want, const char *name) {
  CK_BYTE buf[32]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{type, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OK, name);
  CK_ULONG got = 0;
  if (get[0].ulValueLen == sizeof(CK_ULONG)) memcpy(&got, buf, sizeof got);
  printf("certificates:%s/%s/%s/%s length=%lu value=0x%lx\n", leg, name, version,
    storage, (unsigned long)get[0].ulValueLen, (unsigned long)got);
  REQUIRE(get[0].ulValueLen == sizeof(CK_ULONG) && got == want &&
    filled(buf + sizeof(CK_ULONG), sizeof buf - sizeof(CK_ULONG)), name);
}
static void read_bool(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE type, CK_BBOOL want, const char *name) {
  CK_BYTE buf[8]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{type, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_OK, name);
  printf("certificates:%s/%s/%s/%s length=%lu value=%u\n", leg, name, version,
    storage, (unsigned long)get[0].ulValueLen, buf[0]);
  REQUIRE(get[0].ulValueLen == 1 && buf[0] == (CK_BYTE)want &&
    filled(buf + 1, sizeof buf - 1), name);
}
static void read_absent(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE type, const char *name) {
  CK_BYTE buf[8]; memset(buf, 0xa5, sizeof buf);
  CK_ATTRIBUTE get[] = {{type, buf, sizeof buf}};
  RV(a.GetAttributeValue(h, o, get, N(get)), CKR_ATTRIBUTE_TYPE_INVALID, name);
  REQUIRE(get[0].ulValueLen == CK_UNAVAILABLE_INFORMATION &&
    filled(buf, sizeof buf), name);
}
static unsigned find_all(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG n,
    CK_OBJECT_HANDLE *out, unsigned cap) {
  if (!expect(a.FindObjectsInit(h, tmpl, n), CKR_OK, "find-init")) return 0;
  unsigned total = 0;
  for (;;) {
    CK_OBJECT_HANDLE page[8];
    CK_ULONG got = 0;
    for (unsigned i = 0; i < N(page); ++i) page[i] = SENTINEL;
    if (!expect(a.FindObjects(h, page, N(page), &got), CKR_OK, "find-next")) return 0;
    if (got > N(page)) setup_error("find-overrun");
    for (CK_ULONG i = 0; i < got; ++i) {
      if (total >= cap) setup_error("find-overflow");
      out[total++] = page[i];
    }
    if (got < N(page)) break;
  }
  if (!expect(a.FindObjectsFinal(h), CKR_OK, "find-final")) return 0;
  return total;
}
static void find_contains(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG n,
    CK_OBJECT_HANDLE want, const char *name) {
  CK_OBJECT_HANDLE hits[8];
  for (unsigned i = 0; i < N(hits); ++i) hits[i] = SENTINEL;
  unsigned total = find_all(h, tmpl, n, hits, N(hits));
  if (failed) return;
  unsigned at = 0;
  while (at < total && hits[at] != want) ++at;
  printf("certificates:%s/%s/%s/%s matches=%u\n", leg, name, version, storage, total);
  REQUIRE(at < total, name);
}
static void find_count(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG n,
    unsigned want, const char *name) {
  CK_OBJECT_HANDLE hits[8];
  for (unsigned i = 0; i < N(hits); ++i) hits[i] = SENTINEL;
  unsigned total = find_all(h, tmpl, n, hits, N(hits));
  if (failed) return;
  printf("certificates:%s/%s/%s/%s matches=%u expected=%u\n", leg, name,
    version, storage, total, want);
  REQUIRE(total == want, name);
}
static void destroy(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, const char *name) {
  RV(a.DestroyObject(h, o), CKR_OK, name);
}
static void cleanup(void) {
  if (live) {
    CK_RV rv = a.Finalize(NULL); live = 0;
    if (rv != CKR_OK) setup_error("cleanup-finalize");
  }
  /* Do not dlclose a module with Haskell process-lifetime roots. */
}
static int child(const char *path, unsigned v, unsigned s, unsigned l) {
  struct stat st;
  (void)s;
  if (lstat(directory, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 0777) != 0700)
    setup_error("owned-child-directory");
  /* A process alarm is a crash/timeout, never assertion exit 1. */
  alarm(150);
  configure(l == 3 /* visibility configures two tokens */);
  load_table(path, v);
  load_fixture();
  static void (*const tests[])(void) = {leg_create, leg_find, leg_lifecycle,
    leg_visibility, leg_atomicity, leg_restart};
  if (!failed) tests[l]();
  cleanup(); alarm(0);
  printf("certificates:%s/result/%s/%s assertions=%u failures=%d\n", leg,
    version, storage, assertions, failed);
  printf("CERT-RESULT: %s version=%s storage=%s leg=%s\n",
    failed ? "ASSERT-FAIL" : "PASS", version, storage, leg);
  return failed ? 1 : 0;
}
static void remove_owned(const char *dir) {
  static const char *files[] = {"cert.toml", "tokens.db", "tokens.db-wal",
    "tokens.db-shm", "tokens.db.lock", "tokens.db-journal"};
  char path[PATH_MAX];
  for (unsigned i = 0; i < N(files); ++i) {
    int n = snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
    if (n < 0 || (size_t)n >= sizeof(path)) setup_error("cleanup-path");
    if (unlink(path) && errno != ENOENT) setup_error("cleanup-owned-file");
  }
  if (rmdir(dir)) setup_error("cleanup-owned-directory");
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  version = "setup"; storage = "setup"; leg = "fixture";
  if (argc == 10 && !strcmp(argv[2], "--version") && !strcmp(argv[4], "--storage") &&
      !strcmp(argv[6], "--leg") && !strcmp(argv[8], "--directory")) {
    unsigned v, s, l;
    for (v = 0; v < N(versions) && strcmp(versions[v], argv[3]); ++v) {}
    for (s = 0; s < N(stores) && strcmp(stores[s], argv[5]); ++s) {}
    for (l = 0; l < N(legs) && strcmp(legs[l], argv[7]); ++l) {}
    if (v == N(versions) || s == N(stores) || l == N(legs)) return 2;
    version = versions[v]; storage = stores[s]; leg = legs[l]; directory = argv[9];
    return child(argv[1], v, s, l);
  }
  if (argc != 2) { puts("certificates:setup-error usage"); return 2; }
  if (mkdir("/tmp/haskoki-certificates", 0700) && errno != EEXIST) return 2;
  if (mkdir("/tmp/haskoki-certificates/native", 0700) && errno != EEXIST) return 2;
  char base[] = "/tmp/haskoki-certificates/native/full-XXXXXX";
  if (!mkdtemp(base)) return 2;
  int result = 0;
  for (unsigned v = 0; v < N(versions); ++v) for (unsigned s = 0; s < N(stores); ++s)
    for (unsigned l = 0; l < N(legs); ++l) {
      char dir[PATH_MAX]; int n = snprintf(dir, sizeof(dir), "%s/%u-%u-%u", base, v, s, l);
      if (n < 0 || (size_t)n >= sizeof(dir) || mkdir(dir, 0700)) setup_error("child-directory");
      pid_t pid = fork(); if (pid < 0) setup_error("fork");
      if (!pid) {
        alarm(180);
        execl(argv[0], argv[0], argv[1], "--version", versions[v], "--storage", stores[s],
              "--leg", legs[l], "--directory", dir, (char *)NULL); _exit(2);
      }
      int status;
      while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) setup_error("waitpid");
      int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
      if (rc > 2) rc = 2;
      if (rc > result) result = rc;
      printf("CERT-RESULT: %s version=%s storage=%s leg=%s\n",
        rc == 0 ? "PASS" : rc == 1 ? "ASSERT-FAIL" : "SETUP-FAIL",
        versions[v], stores[s], legs[l]);
      remove_owned(dir);
    }
  if (rmdir(base)) setup_error("parent-directory");
  printf("certificates:matrix legs=48 exit=%d child_leaks=0\n", result);
  return result;
}
