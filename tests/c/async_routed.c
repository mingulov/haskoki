/* Independent PKCS #11 3.2 async table consumer. Task 6 covers attached
 * execution and per-entry behavior; restart/revocation belong to Task 7.
 * Only discovery is resolved by symbol name. No provider header, generated
 * layout, private trampoline, or numeric handle serves as an oracle.
 */
#define _GNU_SOURCE
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#include "pkcs11.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(CK_ULONG) == 8, "independent LP64 CK_ULONG");
_Static_assert(sizeof(void *) == 8, "independent LP64 pointer");
_Static_assert(sizeof(CK_ASYNC_DATA) == 40, "independent async result size");
_Static_assert(offsetof(CK_ASYNC_DATA, ulVersion) == 0, "version offset");
_Static_assert(offsetof(CK_ASYNC_DATA, pValue) == 8, "value offset");
_Static_assert(offsetof(CK_ASYNC_DATA, ulValue) == 16, "length offset");
_Static_assert(offsetof(CK_ASYNC_DATA, hObject) == 24, "object offset");
_Static_assert(offsetof(CK_ASYNC_DATA, hAdditionalObject) == 32,
               "additional object offset");

#define ID_SENTINEL 0xa5a5a5a5a5a5a5a5UL
#define INVALID_SESSION (~0UL)
#define UNKNOWN_ID (~0UL)
#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
  CK_BYTE prefix[16], bytes[64], tail[16];
  CK_ULONG length;
} Output;

typedef struct {
  CK_BYTE prefix[16];
  CK_ASYNC_DATA data;
  CK_BYTE tail[16];
} Result;

typedef struct Race Race;
typedef struct {
  Race *race;
  Result result;
  CK_RV code;
  int barrier_status;
} Completer;
struct Race {
  CK_SESSION_HANDLE session;
  pthread_barrier_t barrier;
  pthread_mutex_t mutex;
  pthread_cond_t ready;
  int start;
  Completer workers[2];
};

static CK_FUNCTION_LIST_3_2 *api;
static CK_SLOT_ID home_slot;
static unsigned failures, assertions;
static int initialized;
static void *module;
static char fixture_dir[256];
static const CK_BYTE sha256_abc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static CK_UTF8CHAR digest_name[] = "C_Digest";
static CK_UTF8CHAR sign_name[] = "C_Sign";

/* Fixture bodies intentionally follow every behavioral assertion. The first
 * recorded build is made with these declarations and no fixture definitions. */
static void fixture_configure(int sqlite);
static CK_C_GetInterface fixture_load(const char *path);
static void fixture_initialize(const char *leg);
static CK_SESSION_HANDLE fixture_session(int async);
static void fixture_close(CK_SESSION_HANDLE session);
static void fixture_finalize(const char *leg);
static void fixture_cleanup(void);
static CK_BYTE *fixture_pages(size_t *page_size);
static void fixture_unmap(CK_BYTE *pages, size_t page_size);
static void fixture_race(Race *race);
static void reset_output(Output *output, CK_ULONG capacity);
static void reset_result(Result *result, CK_BYTE *incoming);

/* Assertion helpers: a dropped route, early publication, rebound allocation,
 * wrong selector/precedence, or extra completion must fail independently of
 * provider implementation details. */
static void check(const char *entry, const char *leg, int good) {
  ++assertions;
  printf("async:%s/%s/3.2 check=%s\n", entry, leg, good ? "ok" : "FAIL");
  if (!good) ++failures;
}

static const char *rv_name(CK_RV code) {
  switch (code) {
  case CKR_OK: return "CKR_OK";
  case CKR_PENDING: return "CKR_PENDING";
  case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
  case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
  case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
  case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
  case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
  case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
  case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
  case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
  case CKR_SESSION_ASYNC_NOT_SUPPORTED: return "CKR_SESSION_ASYNC_NOT_SUPPORTED";
  case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
  case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
  default: return "CKR_UNEXPECTED";
  }
}

static int expect_rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  ++assertions;
  printf("async:%s/%s/3.2 rv=%s(0x%lx) expected=%s(0x%lx)\n",
         entry, leg, rv_name(got), got, rv_name(want), want);
  /* No table leg has CKR_FUNCTION_NOT_SUPPORTED in its success set. */
  if (got != want || got == CKR_FUNCTION_NOT_SUPPORTED) {
    ++failures;
    return 0;
  }
  return 1;
}

static int all_a5(const void *memory, size_t size) {
  const CK_BYTE *bytes = memory;
  for (size_t i = 0; i < size; ++i)
    if (bytes[i] != 0xa5) return 0;
  return 1;
}

static void same_output(const char *entry, const char *leg,
                        const Output *got, const Output *before) {
  check(entry, leg, memcmp(got, before, sizeof(*got)) == 0);
}

static void same_result(const char *leg, const Result *got,
                        const Result *before) {
  /* Includes every one of the 40 public bytes and both adjacent canaries. */
  check("C_AsyncComplete", leg, memcmp(got, before, sizeof(*got)) == 0);
}

static void clean_output(const char *entry, const char *leg,
                         const Output *output, CK_ULONG length) {
  printf("async:%s/%s/3.2 length=%lu expected=%lu\n",
         entry, leg, output->length, length);
  check(entry, leg, output->length == length &&
        all_a5(output->prefix, sizeof(output->prefix)) &&
        all_a5(output->bytes, sizeof(output->bytes)) &&
        all_a5(output->tail, sizeof(output->tail)));
}

static void digest_bytes(const char *entry, const char *leg,
                         const Output *output) {
  printf("async:%s/%s/3.2 length=32 hex=", entry, leg);
  for (size_t i = 0; i < sizeof(sha256_abc); ++i)
    printf("%02x", output->bytes[i]);
  putchar('\n');
  check(entry, leg, memcmp(output->bytes, sha256_abc, sizeof(sha256_abc)) == 0 &&
        all_a5(output->prefix, sizeof(output->prefix)) &&
        all_a5(output->bytes + 32, sizeof(output->bytes) - 32) &&
        all_a5(output->tail, sizeof(output->tail)));
}

static void delivered(const char *leg, const Result *result,
                      const Output *output, CK_ULONG original_capacity) {
  printf("async:C_AsyncComplete/%s/3.2 length=%lu expected=32\n",
         leg, result->data.ulValue);
  check("C_AsyncComplete", leg,
        result->data.ulVersion == 0 && result->data.pValue == output->bytes &&
        result->data.ulValue == 32 && result->data.hObject == 0 &&
        result->data.hAdditionalObject == 0 &&
        all_a5(result->prefix, sizeof(result->prefix)) &&
        all_a5(result->tail, sizeof(result->tail)));
  check("C_Digest", "original-length-not-retained",
        output->length == original_capacity);
  digest_bytes("C_AsyncComplete", leg, output);
}

static int digest_init(CK_SESSION_HANDLE session, const char *leg) {
  CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
  return expect_rv("C_DigestInit", leg,
                   api->C_DigestInit(session, &mechanism), CKR_OK);
}

static int submit(CK_SESSION_HANDLE session, Output *output,
                  CK_ULONG capacity, const char *leg) {
  CK_BYTE input[] = {'a', 'b', 'c'};
  reset_output(output, capacity);
  Output before = *output;
  if (!digest_init(session, leg)) return 0;
  int good = expect_rv("C_Digest", leg,
      api->C_Digest(session, input, sizeof(input), output->bytes,
                    &output->length), CKR_PENDING);
  same_output("C_Digest", "pending-output-and-length", output, &before);
  /* Subsequent completion must use the submitted bytes, not this address.
   * Volatile stores prevent optimization of the ownership test away. */
  volatile CK_BYTE *overwrite = input;
  for (size_t i = 0; i < sizeof(input); ++i) overwrite[i] = 0xa5;
  check("C_Digest", "input-overwritten-after-submission",
        input[0] == 0xa5 && input[1] == 0xa5 && input[2] == 0xa5);
  return good;
}

static void refuse_complete(CK_SESSION_HANDLE session, CK_UTF8CHAR *name,
                            CK_RV want, Output *output, const char *leg) {
  Result result;
  reset_result(&result, output->bytes);
  Result before = result;
  Output saved = *output;
  expect_rv("C_AsyncComplete", leg,
            api->C_AsyncComplete(session, name, &result.data), want);
  same_result(leg, &result, &before);
  same_output("C_AsyncComplete", leg, output, &saved);
}

static void refuse_id(CK_SESSION_HANDLE session, CK_UTF8CHAR *name,
                      CK_RV want, Output *output, const char *leg) {
  CK_ULONG id = ID_SENTINEL;
  Output saved = *output;
  expect_rv("C_AsyncGetID", leg, api->C_AsyncGetID(session, name, &id), want);
  check("C_AsyncGetID", leg, id == ID_SENTINEL);
  same_output("C_AsyncGetID", leg, output, &saved);
}

static void refuse_join(CK_SESSION_HANDLE session, CK_UTF8CHAR *name,
                        CK_ULONG id, CK_BYTE *buffer, CK_ULONG capacity,
                        CK_RV want, Output *output, const char *leg) {
  Output saved = *output;
  expect_rv("C_AsyncJoin", leg,
            api->C_AsyncJoin(session, name, id, buffer, capacity), want);
  same_output("C_AsyncJoin", leg, output, &saved);
}

static void complete_pair(CK_SESSION_HANDLE session, Output *output,
                          Result *result, const char *leg) {
  char pending[128];
  snprintf(pending, sizeof(pending), "%s-pending", leg);
  Result before = *result;
  Output saved = *output;
  CK_ULONG capacity = output->length;
  expect_rv("C_AsyncComplete", pending,
            api->C_AsyncComplete(session, digest_name, &result->data),
            CKR_PENDING);
  same_result(pending, result, &before);
  same_output("C_AsyncComplete", pending, output, &saved);
  expect_rv("C_AsyncComplete", leg,
            api->C_AsyncComplete(session, digest_name, &result->data), CKR_OK);
  delivered(leg, result, output, capacity);
}

static CK_ULONG detach(CK_SESSION_HANDLE session, Output *output,
                       CK_ULONG initial_id, const char *leg) {
  CK_ULONG id = initial_id;
  Output before = *output;
  expect_rv("C_AsyncGetID", leg,
            api->C_AsyncGetID(session, digest_name, &id), CKR_OK);
  check("C_AsyncGetID", "scalar-id-published", id != 0 && id != initial_id);
  same_output("C_AsyncGetID", leg, output, &before);
  refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                  output, "after-detach");
  refuse_id(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
            output, "repeat-after-detach");
  return id;
}

static void join_ok(CK_SESSION_HANDLE session, CK_ULONG id, Output *output,
                    CK_ULONG capacity, const char *leg) {
  Output before = *output;
  expect_rv("C_AsyncJoin", leg,
            api->C_AsyncJoin(session, digest_name, id, output->bytes, capacity),
            CKR_OK);
  same_output("C_AsyncJoin", leg, output, &before);
}

static int discovery(CK_C_GetInterface get_interface) {
  CK_VERSION requested = {3, 2}, actual = {0, 0};
  CK_INTERFACE_PTR interface = NULL;
  if (!expect_rv("C_GetInterface", "discover-before-init",
                 get_interface(NULL, &requested, &interface, 0), CKR_OK))
    return 0;
  check("C_GetInterface", "table-present",
        interface != NULL && interface->pFunctionList != NULL);
  if (interface == NULL || interface->pFunctionList == NULL) return 0;
  /* Read only the common version prefix before trusting the table's extent. */
  memcpy(&actual, interface->pFunctionList, sizeof(actual));
  check("C_GetInterface", "version", actual.major == 3 && actual.minor == 2);
  if (actual.major != 3 || actual.minor != 2) return 0;
  api = interface->pFunctionList;
  check("C_AsyncComplete", "slot-present", api->C_AsyncComplete != NULL);
  check("C_AsyncGetID", "slot-present", api->C_AsyncGetID != NULL);
  check("C_AsyncJoin", "slot-present", api->C_AsyncJoin != NULL);
  check("fixture", "standard-members-present",
        api->C_Initialize && api->C_Finalize && api->C_GetSlotList &&
        api->C_GetTokenInfo && api->C_OpenSession && api->C_CloseSession &&
        api->C_GetSessionInfo && api->C_DigestInit && api->C_Digest &&
        api->C_DigestUpdate && api->C_DigestFinal && api->C_Sign &&
        api->C_SessionCancel);
  return failures == 0;
}

static void lifecycle(const char *phase) {
  static const char *const shapes[] = {
    "null-name", "null-output", "both-null", "well-shaped"
  };
  for (size_t i = 0; i < ARRAY_COUNT(shapes); ++i) {
    Output output;
    Result result;
    CK_ULONG id = ID_SENTINEL;
    char leg[128];
    reset_output(&output, 32);
    reset_result(&result, output.bytes);
    Output saved = output;
    Result before = result;
    snprintf(leg, sizeof(leg), "%s-%s", phase, shapes[i]);
    CK_UTF8CHAR *name = (i == 0 || i == 2) ? NULL : digest_name;
    expect_rv("C_AsyncComplete", leg,
        api->C_AsyncComplete(INVALID_SESSION, name,
                            (i == 1 || i == 2) ? NULL : &result.data),
        CKR_CRYPTOKI_NOT_INITIALIZED);
    same_result(leg, &result, &before);
    same_output("C_AsyncComplete", leg, &output, &saved);
    expect_rv("C_AsyncGetID", leg,
        api->C_AsyncGetID(INVALID_SESSION, name,
                         (i == 1 || i == 2) ? NULL : &id),
        CKR_CRYPTOKI_NOT_INITIALIZED);
    check("C_AsyncGetID", leg, id == ID_SENTINEL);
    same_output("C_AsyncGetID", leg, &output, &saved);
  }
  /* Include both accepted zero shapes as well as every structural null
   * combination; liveness must win before session, name, id, or capacity. */
  for (unsigned i = 0; i < 7; ++i) {
    static const char *const join_shapes[] = {
      "null-name", "null-nonzero", "both-null-nonzero",
      "null-zero", "present-zero", "both-null-zero", "well-shaped"
    };
    Output output;
    char leg[128];
    reset_output(&output, 32);
    snprintf(leg, sizeof(leg), "%s-%s", phase, join_shapes[i]);
    refuse_join(INVALID_SESSION,
                (i == 0 || i == 2 || i == 5) ? NULL : digest_name,
                UNKNOWN_ID,
                (i == 1 || i == 2 || i == 3 || i == 5) ? NULL : output.bytes,
                (i == 3 || i == 4 || i == 5) ? 0 : 32,
                CKR_CRYPTOKI_NOT_INITIALIZED, &output, leg);
  }
}

static void guards_and_names(void) {
  CK_SESSION_HANDLE session = fixture_session(1);
  CK_SESSION_HANDLE other = fixture_session(1);
  Output output, spare;
  Result result;
  reset_output(&spare, 32);
  if (!submit(session, &output, 32, "guards-source")) goto done;
  for (unsigned invalid = 0; invalid < 2; ++invalid) {
    CK_SESSION_HANDLE selected = invalid ? INVALID_SESSION : session;
    const char *scope = invalid ? "invalid-session" : "valid-session";
    for (unsigned shape = 0; shape < 3; ++shape) {
      char leg[128];
      static const char *const shapes[] = {"null-name", "null-output", "both-null"};
      snprintf(leg, sizeof(leg), "live-%s-%s", scope, shapes[shape]);
      CK_UTF8CHAR *name = shape == 1 ? digest_name : NULL;
      reset_result(&result, spare.bytes);
      Result before = result;
      Output saved = output;
      CK_ULONG id = ID_SENTINEL;
      expect_rv("C_AsyncComplete", leg,
          api->C_AsyncComplete(selected, name, shape == 0 ? &result.data : NULL),
          CKR_ARGUMENTS_BAD);
      same_result(leg, &result, &before);
      same_output("C_AsyncComplete", leg, &output, &saved);
      expect_rv("C_AsyncGetID", leg,
          api->C_AsyncGetID(selected, name, shape == 0 ? &id : NULL),
          CKR_ARGUMENTS_BAD);
      check("C_AsyncGetID", leg, id == ID_SENTINEL);
      same_output("C_AsyncGetID", leg, &output, &saved);
      refuse_join(selected, name, UNKNOWN_ID,
                  shape == 0 ? spare.bytes : NULL, 32,
                  CKR_ARGUMENTS_BAD, &spare, leg);
    }
  }
  CK_UTF8CHAR unterminated[32];
  CK_UTF8CHAR last_nul[32];
  CK_UTF8CHAR non_ascii[] = {0x80, 0};
  memset(unterminated, 'x', sizeof(unterminated));
  memset(last_nul, 'x', sizeof(last_nul));
  last_nul[31] = 0;
  struct {
    const char *leg;
    CK_UTF8CHAR *name;
  } names[] = {
    {"empty", (CK_UTF8CHAR *)""},
    {"case-prefix", (CK_UTF8CHAR *)"c_Digest"},
    {"case-body", (CK_UTF8CHAR *)"C_DIGEST"},
    {"suffix", (CK_UTF8CHAR *)"C_Digestx"},
    {"non-ascii", non_ascii},
    {"numeric-sign", (CK_UTF8CHAR *)"1"},
    {"numeric-digest", (CK_UTF8CHAR *)"2"},
    {"short-sign", (CK_UTF8CHAR *)"sign"},
    {"short-digest", (CK_UTF8CHAR *)"digest"},
    {"unsupported-key", (CK_UTF8CHAR *)"C_GenerateKey"},
    {"unsupported-key-pair", (CK_UTF8CHAR *)"C_GenerateKeyPair"},
    {"unterminated-32", unterminated},
    {"terminator-at-32", last_nul}
  };
  for (size_t i = 0; i < ARRAY_COUNT(names); ++i) {
    char leg[128];
    snprintf(leg, sizeof(leg), "name-%s", names[i].leg);
    refuse_complete(session, names[i].name, CKR_ARGUMENTS_BAD, &output, leg);
    refuse_id(session, names[i].name, CKR_ARGUMENTS_BAD, &output, leg);
    refuse_join(other, names[i].name, UNKNOWN_ID, spare.bytes, 32,
                CKR_ARGUMENTS_BAD, &spare, leg);
    snprintf(leg, sizeof(leg), "session-before-%s", names[i].leg);
    refuse_complete(INVALID_SESSION, names[i].name, CKR_SESSION_HANDLE_INVALID,
                    &output, leg);
    refuse_id(INVALID_SESSION, names[i].name, CKR_SESSION_HANDLE_INVALID,
              &output, leg);
    refuse_join(INVALID_SESSION, names[i].name, UNKNOWN_ID, spare.bytes, 0,
                CKR_SESSION_HANDLE_INVALID, &spare, leg);
  }
  refuse_complete(INVALID_SESSION, digest_name, CKR_SESSION_HANDLE_INVALID,
                  &output, "invalid-session");
  refuse_id(INVALID_SESSION, digest_name, CKR_SESSION_HANDLE_INVALID,
            &output, "invalid-session");
  refuse_join(INVALID_SESSION, digest_name, UNKNOWN_ID, spare.bytes, 32,
              CKR_SESSION_HANDLE_INVALID, &spare, "invalid-session");
  refuse_join(INVALID_SESSION, digest_name, UNKNOWN_ID, NULL, 0,
              CKR_SESSION_HANDLE_INVALID, &spare, "session-before-null-zero");
  refuse_complete(session, sign_name, CKR_OPERATION_NOT_INITIALIZED,
                  &output, "sign-does-not-select-digest");
  refuse_id(session, sign_name, CKR_OPERATION_NOT_INITIALIZED,
            &output, "sign-does-not-select-digest");
  refuse_complete(other, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                  &output, "other-session");
  refuse_id(other, digest_name, CKR_OPERATION_NOT_INITIALIZED,
            &output, "other-session");
  CK_UTF8CHAR suffix[] = "C_Digest\0junk";
  refuse_complete(other, suffix, CKR_OPERATION_NOT_INITIALIZED,
                  &output, "nul-ignores-suffix");
  refuse_id(other, suffix, CKR_OPERATION_NOT_INITIALIZED,
            &output, "nul-ignores-suffix");
  reset_result(&result, spare.bytes);
  complete_pair(session, &output, &result, "guards-preserve-two-polls");
  clean_output("C_AsyncComplete", "alternate-guard-output", &spare, 32);
done:
  fixture_close(other);
  fixture_close(session);
}

static void attached_fields(void) {
  for (unsigned alternate = 0; alternate < 2; ++alternate) {
    const char *leg = alternate ? "public-alternate-zero-capacity" : "public-null-zero";
    CK_SESSION_HANDLE session = fixture_session(1);
    Output output, spare;
    Result result;
    reset_output(&spare, 0);
    if (submit(session, &output, 32, leg)) {
      reset_result(&result, NULL);
      if (alternate) {
        result.data.pValue = spare.bytes;
        result.data.ulValue = 0;
      } else {
        memset(&result.data, 0, sizeof(result.data));
        result.data.pValue = NULL;
      }
      complete_pair(session, &output, &result, leg);
      clean_output("C_AsyncComplete", "alternate-not-rebound", &spare, 0);
      refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                      &output, "repeat-complete");
      refuse_id(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                &output, "get-id-after-delivery");
    }
    fixture_close(session);
  }
}

static void synchronous_controls(void) {
  CK_BYTE input[] = {'a', 'b', 'c'};
  for (unsigned shape = 0; shape < 4; ++shape) {
    static const char *const legs[] = {
      "ordinary", "null-query", "present-zero", "short-31"
    };
    CK_SESSION_HANDLE session = fixture_session(shape != 0);
    Output output;
    CK_ULONG capacity = shape == 2 ? 0 : shape == 3 ? 31 : 32;
    /* Poison query length so the assertion proves that 32 was published. */
    reset_output(&output, shape == 1 ? 0xa5a5a5a5a5a5a5a5UL : capacity);
    if (digest_init(session, legs[shape])) {
      expect_rv("C_Digest", legs[shape],
          api->C_Digest(session, input, sizeof(input),
                        shape == 1 ? NULL : output.bytes, &output.length),
          shape >= 2 ? CKR_BUFFER_TOO_SMALL : CKR_OK);
      check("C_Digest", legs[shape], output.length == 32);
      if (shape == 0) digest_bytes("C_Digest", "ordinary", &output);
      else clean_output("C_Digest", legs[shape], &output, 32);
      refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                      &output, legs[shape]);
      refuse_id(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                &output, legs[shape]);
      if (shape != 0) {
        expect_rv("C_Digest", "adequate-staged-recall",
            api->C_Digest(session, input, sizeof(input), output.bytes,
                          &output.length), CKR_OK);
        check("C_Digest", "staged-recall-length", output.length == 32);
        digest_bytes("C_Digest", "adequate-staged-recall", &output);
        refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                        &output, "staged-recall-no-job");
      }
    }
    fixture_close(session);
  }
}

static void occupied_and_classic_refusals(void) {
  CK_BYTE input[] = {'x', 'y', 'z'};
  CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
  CK_SESSION_HANDLE session = fixture_session(1);
  Output output, spare;
  Result result;
  reset_output(&spare, 32);
  if (submit(session, &output, 32, "occupied-source")) {
    expect_rv("C_Digest", "occupied",
        api->C_Digest(session, input, sizeof(input), spare.bytes, &spare.length),
        CKR_OPERATION_ACTIVE);
    expect_rv("C_DigestInit", "occupied",
              api->C_DigestInit(session, &mechanism), CKR_OPERATION_ACTIVE);
    expect_rv("C_DigestUpdate", "occupied",
              api->C_DigestUpdate(session, input, sizeof(input)), CKR_OPERATION_ACTIVE);
    expect_rv("C_DigestFinal", "occupied",
              api->C_DigestFinal(session, spare.bytes, &spare.length),
              CKR_OPERATION_ACTIVE);
    /* A classic structural refusal in Sign must not retire Digest. */
    expect_rv("C_Sign", "invalid-unrelated-slot",
              api->C_Sign(session, NULL, 1, spare.bytes, NULL), CKR_ARGUMENTS_BAD);
    clean_output("C_Digest", "occupied-spare-unchanged", &spare, 32);
    reset_result(&result, NULL);
    complete_pair(session, &output, &result, "occupied-binding-preserved");
  }
  fixture_close(session);
  for (unsigned shape = 0; shape < 4; ++shape) {
    static const char *const legs[] = {
      "classic-null-length", "classic-null-input",
      "classic-update-null-input", "classic-final-null-length"
    };
    CK_SESSION_HANDLE victim = fixture_session(1);
    CK_SESSION_HANDLE keeper = fixture_session(1);
    Output victim_out, keeper_out;
    reset_output(&spare, 32);
    int victim_started = submit(victim, &victim_out, 32, legs[shape]);
    int keeper_started = submit(keeper, &keeper_out, 32, "classic-other-session");
    if (victim_started && keeper_started) {
      CK_RV code;
      if (shape == 0)
        code = api->C_Digest(victim, input, sizeof(input), spare.bytes, NULL);
      else if (shape == 1)
        code = api->C_Digest(victim, NULL, 1, spare.bytes, &spare.length);
      else if (shape == 2)
        code = api->C_DigestUpdate(victim, NULL, 1);
      else code = api->C_DigestFinal(victim, spare.bytes, NULL);
      expect_rv(shape < 2 ? "C_Digest" : shape == 2 ? "C_DigestUpdate" :
                "C_DigestFinal", legs[shape], code, CKR_ARGUMENTS_BAD);
      refuse_complete(victim, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                      &victim_out, legs[shape]);
      refuse_id(victim, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                &victim_out, legs[shape]);
      clean_output("C_Digest", "classic-victim-not-written", &victim_out, 32);
      clean_output("C_Digest", "classic-spare-not-written", &spare, 32);
      reset_result(&result, NULL);
      complete_pair(keeper, &keeper_out, &result, "classic-other-binding-retained");
    }
    fixture_close(keeper);
    fixture_close(victim);
  }
}

static void memory_no_store(void) {
  CK_SESSION_HANDLE session = fixture_session(1);
  CK_SESSION_HANDLE target = fixture_session(1);
  Output output, spare;
  Result result;
  reset_output(&spare, 32);
  if (submit(session, &output, 32, "memory-no-store")) {
    CK_ULONG id = ID_SENTINEL;
    expect_rv("C_AsyncGetID", "memory-no-store",
              api->C_AsyncGetID(session, digest_name, &id), CKR_GENERAL_ERROR);
    check("C_AsyncGetID", "memory-id-zero", id == 0);
    clean_output("C_AsyncGetID", "memory-output-retained", &output, 32);
    digest_init(target, "memory-join-target");
    refuse_join(target, digest_name, UNKNOWN_ID, spare.bytes, 32,
                CKR_GENERAL_ERROR, &spare, "memory-no-store");
    reset_result(&result, NULL);
    complete_pair(session, &output, &result, "memory-refusal-retains-binding");
  }
  fixture_close(target);
  fixture_close(session);
}

static void cancellations(void) {
  for (unsigned mode = 0; mode < 3; ++mode) {
    static const char *const legs[] = {
      "cancel-first", "completion-first", "unrelated-selector"
    };
    CK_SESSION_HANDLE session = fixture_session(1);
    Output output;
    Result result;
    if (submit(session, &output, 32, legs[mode])) {
      reset_result(&result, NULL);
      if (mode == 1) complete_pair(session, &output, &result, legs[mode]);
      Output before = output;
      expect_rv("C_SessionCancel", legs[mode],
                api->C_SessionCancel(session, mode == 2 ? CKF_SIGN : CKF_DIGEST),
                CKR_OK);
      same_output("C_SessionCancel", legs[mode], &output, &before);
      if (mode == 2) complete_pair(session, &output, &result, legs[mode]);
      else {
        refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                        &output, legs[mode]);
        refuse_id(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                  &output, legs[mode]);
        if (mode == 0)
          clean_output("C_SessionCancel", "cancel-first-no-delivery", &output, 32);
        else digest_bytes("C_SessionCancel", "completion-cannot-be-undone", &output);
      }
    }
    fixture_close(session);
  }
}

/* Workers do not print or modify shared assertion counters. The coordinator
 * joins them, then normalizes winner/loser labels independently of scheduling. */
static void *completer_thread(void *argument) {
  Completer *worker = argument;
  Race *race = worker->race;
  pthread_mutex_lock(&race->mutex);
  while (race->start == 0) pthread_cond_wait(&race->ready, &race->mutex);
  int run = race->start > 0;
  pthread_mutex_unlock(&race->mutex);
  if (!run) return NULL;
  worker->barrier_status = pthread_barrier_wait(&race->barrier);
  if (worker->barrier_status == 0 ||
      worker->barrier_status == PTHREAD_BARRIER_SERIAL_THREAD)
    worker->code = api->C_AsyncComplete(race->session, digest_name,
                                       &worker->result.data);
  return NULL;
}

static void concurrent_completers(void) {
  CK_SESSION_HANDLE session = fixture_session(1);
  Output output;
  Result pending;
  if (submit(session, &output, 32, "concurrent-source")) {
    reset_result(&pending, NULL);
    Result before = pending;
    Output saved = output;
    expect_rv("C_AsyncComplete", "concurrent-first-pending",
              api->C_AsyncComplete(session, digest_name, &pending.data),
              CKR_PENDING);
    same_result("concurrent-first-pending", &pending, &before);
    same_output("C_AsyncComplete", "concurrent-first-pending", &output, &saved);
    Race race = {.session = session};
    Result snapshots[2];
    for (unsigned i = 0; i < 2; ++i) {
      race.workers[i].race = &race;
      race.workers[i].code = CKR_GENERAL_ERROR;
      reset_result(&race.workers[i].result, NULL);
      snapshots[i] = race.workers[i].result;
    }
    fixture_race(&race);
    unsigned winners = 0, losers = 0;
    for (unsigned i = 0; i < 2; ++i) {
      Completer *worker = &race.workers[i];
      check("C_AsyncComplete", "concurrent-barrier",
            worker->barrier_status == 0 ||
            worker->barrier_status == PTHREAD_BARRIER_SERIAL_THREAD);
      winners += worker->code == CKR_OK;
      losers += worker->code == CKR_OPERATION_NOT_INITIALIZED;
    }
    check("C_AsyncComplete", "concurrent-exactly-one-winner-and-loser",
          winners == 1 && losers == 1);
    /* Always print the winner before the loser, regardless of thread order.
     * On failure these selections still report the unexpected return codes. */
    unsigned winner = race.workers[0].code == CKR_OK ? 0 : 1;
    unsigned loser = 1 - winner;
    expect_rv("C_AsyncComplete", "concurrent-winner",
              race.workers[winner].code, CKR_OK);
    if (race.workers[winner].code == CKR_OK)
      delivered("concurrent-one-delivery", &race.workers[winner].result, &output, 32);
    expect_rv("C_AsyncComplete", "concurrent-loser", race.workers[loser].code,
              CKR_OPERATION_NOT_INITIALIZED);
    same_result("concurrent-loser-untouched", &race.workers[loser].result,
                &snapshots[loser]);
    digest_bytes("C_AsyncComplete", "concurrent-canaries", &output);
    /* Repaint the delivered allocation: an illicit later delivery would now
     * be observable, rather than hidden by writing the same digest twice. */
    reset_output(&output, 32);
    refuse_complete(session, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                    &output, "concurrent-no-later-write");
    clean_output("C_AsyncComplete", "concurrent-repaint-preserved", &output, 32);
  }
  fixture_close(session);
}

static void selector_pages(void) {
  size_t page_size;
  CK_BYTE *pages = fixture_pages(&page_size);
  CK_BYTE *end = pages + page_size;
  CK_SESSION_HANDLE session = fixture_session(1);
  CK_SESSION_HANDLE other = fixture_session(1);
  Output output, spare;
  Result result;
  reset_output(&spare, 32);
  if (!submit(session, &output, 32, "page-source")) goto done;
  /* Even wholly unreadable contents must not beat invalid-session lookup. */
  refuse_complete(INVALID_SESSION, end, CKR_SESSION_HANDLE_INVALID,
                  &output, "page-session-before-read");
  refuse_id(INVALID_SESSION, end, CKR_SESSION_HANDLE_INVALID,
            &output, "page-session-before-read");
  refuse_join(INVALID_SESSION, end, UNKNOWN_ID, spare.bytes, 0,
              CKR_SESSION_HANDLE_INVALID, &spare, "page-session-before-read");
  memset(end - 32, 'x', 32);
  refuse_complete(session, end - 32, CKR_ARGUMENTS_BAD,
                  &output, "page-bound-32");
  refuse_id(session, end - 32, CKR_ARGUMENTS_BAD, &output, "page-bound-32");
  refuse_join(other, end - 32, UNKNOWN_ID, spare.bytes, 32,
              CKR_ARGUMENTS_BAD, &spare, "page-bound-32");
  end[-1] = 0;
  refuse_complete(session, end - 32, CKR_ARGUMENTS_BAD,
                  &output, "page-final-permitted-nul");
  refuse_id(session, end - 32, CKR_ARGUMENTS_BAD,
            &output, "page-final-permitted-nul");
  refuse_join(other, end - 32, UNKNOWN_ID, spare.bytes, 32,
              CKR_ARGUMENTS_BAD, &spare, "page-final-permitted-nul");
  memcpy(end - sizeof(digest_name), digest_name, sizeof(digest_name));
  CK_UTF8CHAR *bounded_name = end - sizeof(digest_name);
  CK_ULONG id = ID_SENTINEL;
  expect_rv("C_AsyncGetID", "page-stop-at-nul",
            api->C_AsyncGetID(session, bounded_name, &id), CKR_GENERAL_ERROR);
  check("C_AsyncGetID", "page-no-store-id-zero", id == 0);
  clean_output("C_AsyncGetID", "page-no-store-buffer", &output, 32);
  refuse_join(other, bounded_name, UNKNOWN_ID, spare.bytes, 32,
              CKR_GENERAL_ERROR, &spare, "page-stop-at-nul");
  reset_result(&result, NULL);
  Result before = result;
  Output saved = output;
  expect_rv("C_AsyncComplete", "page-stop-at-nul",
            api->C_AsyncComplete(session, bounded_name, &result.data), CKR_PENDING);
  same_result("page-stop-at-nul", &result, &before);
  same_output("C_AsyncComplete", "page-stop-at-nul", &output, &saved);
  expect_rv("C_AsyncComplete", "page-delivery",
            api->C_AsyncComplete(session, bounded_name, &result.data), CKR_OK);
  delivered("page-delivery", &result, &output, 32);
done:
  fixture_close(other);
  fixture_close(session);
  fixture_unmap(pages, page_size);
}

static void sqlite_join_matrix(void) {
  CK_SESSION_HANDLE source = fixture_session(1);
  CK_SESSION_HANDLE target = fixture_session(1);
  CK_SESSION_HANDLE observer = fixture_session(1);
  CK_SESSION_HANDLE ordinary = fixture_session(0);
  CK_SESSION_HANDLE source_two = fixture_session(1);
  Output old, bound, spare, old_two;
  Result result;
  reset_output(&bound, 32);
  reset_output(&spare, 32);
  if (!submit(source, &old, 32, "sqlite-source")) goto done;
  CK_ULONG id = detach(source, &old, ID_SENTINEL, "sqlite-detach");
  expect_rv("C_SessionCancel", "detached-source",
            api->C_SessionCancel(source, CKF_DIGEST), CKR_OK);
  /* Closing the source must not cancel the now idle durable record. */
  fixture_close(source);
  source = CK_INVALID_HANDLE;
  digest_init(observer, "join-observer");
  digest_init(ordinary, "join-ordinary");
  refuse_join(target, digest_name, UNKNOWN_ID, bound.bytes, 32,
              CKR_SAVED_STATE_INVALID, &bound, "unknown-id");
  refuse_join(target, digest_name, UNKNOWN_ID, bound.bytes, 0,
              CKR_SAVED_STATE_INVALID, &bound, "unknown-id-before-zero-capacity");
  refuse_join(target, digest_name, UNKNOWN_ID, NULL, 0,
              CKR_SAVED_STATE_INVALID, &bound, "unknown-id-before-null-zero");
  refuse_join(target, sign_name, id, bound.bytes, 32,
              CKR_ARGUMENTS_BAD, &bound, "idle-id-wrong-function");
  refuse_join(ordinary, digest_name, id, spare.bytes, 32,
              CKR_SESSION_ASYNC_NOT_SUPPORTED, &spare, "ordinary-target");
  refuse_join(target, digest_name, id, bound.bytes, 32,
              CKR_OPERATION_NOT_INITIALIZED, &bound, "missing-digest-init");
  digest_init(target, "join-fresh-matching-init");
  refuse_join(target, digest_name, id, NULL, 32,
              CKR_ARGUMENTS_BAD, &bound, "null-nonzero-capacity");
  refuse_join(target, digest_name, id, NULL, 0,
              CKR_ARGUMENTS_BAD, &bound, "null-zero-capacity");
  refuse_join(target, digest_name, id, bound.bytes, 0,
              CKR_ARGUMENTS_BAD, &bound, "present-zero-capacity");
  refuse_join(target, digest_name, id, bound.bytes, 1,
              CKR_BUFFER_TOO_SMALL, &bound, "short-capacity-1");
  refuse_join(target, digest_name, id, bound.bytes, 31,
              CKR_BUFFER_TOO_SMALL, &bound, "short-capacity-31");
  join_ok(target, id, &bound, 32, "retry-capacity-32");
  refuse_join(observer, digest_name, id, spare.bytes, 32,
              CKR_OPERATION_ACTIVE, &spare, "attached-id");
  refuse_join(observer, sign_name, id, spare.bytes, 32,
              CKR_OPERATION_ACTIVE, &spare, "active-id-before-sign");
  refuse_join(observer, digest_name, id, spare.bytes, 1,
              CKR_OPERATION_ACTIVE, &spare, "active-id-before-short");
  refuse_complete(observer, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                  &spare, "join-refusals-install-nothing");
  refuse_id(observer, digest_name, CKR_OPERATION_NOT_INITIALIZED,
            &spare, "join-refusals-install-nothing");
  if (submit(source_two, &old_two, 32, "occupied-target-source")) {
    CK_ULONG second_id = detach(source_two, &old_two, 0, "detach-zero-incoming-id");
    refuse_join(target, digest_name, second_id, spare.bytes, 32,
                CKR_OPERATION_ACTIVE, &spare, "occupied-target");
    clean_output("C_AsyncJoin", "occupied-original-binding", &bound, 32);
    join_ok(observer, second_id, &spare, 32, "occupied-refusal-retry");
    reset_result(&result, NULL);
    complete_pair(observer, &spare, &result, "occupied-refusal-retry-delivery");
    clean_output("C_AsyncGetID", "second-old-output-never-written", &old_two, 32);
  }
  reset_result(&result, NULL);
  complete_pair(target, &bound, &result, "joined-delivery");
  refuse_complete(target, digest_name, CKR_OPERATION_NOT_INITIALIZED,
                  &bound, "joined-repeat");
  refuse_id(target, digest_name, CKR_OPERATION_NOT_INITIALIZED,
            &bound, "sqlite-get-id-after-delivery");
  refuse_join(observer, digest_name, id, spare.bytes, 32,
              CKR_ARGUMENTS_BAD, &spare, "delivered-id");
  clean_output("C_AsyncGetID", "old-output-never-written", &old, 32);
done:
  fixture_close(source_two);
  fixture_close(ordinary);
  fixture_close(observer);
  fixture_close(target);
  if (source != CK_INVALID_HANDLE) fixture_close(source);
}

static void conservative_capacity(void) {
  CK_SESSION_HANDLE source = fixture_session(1);
  CK_SESSION_HANDLE target = fixture_session(1);
  Output old, bound;
  Result result;
  reset_output(&bound, 64);
  if (submit(source, &old, 64, "original-capacity-64")) {
    CK_ULONG id = detach(source, &old, ID_SENTINEL, "detach-capacity-64");
    digest_init(target, "conservative-target");
    refuse_join(target, digest_name, id, bound.bytes, 32,
                CKR_BUFFER_TOO_SMALL, &bound, "pending-64-refuses-32");
    join_ok(target, id, &bound, 64, "pending-64-retry-64");
    reset_result(&result, NULL);
    complete_pair(target, &bound, &result, "capacity-64-eventual-length-32");
    clean_output("C_AsyncGetID", "capacity-64-old-untouched", &old, 64);
  }
  fixture_close(target);
  fixture_close(source);
}

static void joined_cancellation(void) {
  for (unsigned completion_first = 0; completion_first < 2; ++completion_first) {
    const char *leg = completion_first ? "joined-completion-first" : "joined-cancel-first";
    CK_SESSION_HANDLE source = fixture_session(1);
    CK_SESSION_HANDLE target = fixture_session(1);
    CK_SESSION_HANDLE retry = fixture_session(1);
    Output old, bound, spare;
    Result result;
    reset_output(&bound, 32);
    reset_output(&spare, 32);
    if (submit(source, &old, 32, leg)) {
      CK_ULONG id = detach(source, &old, ID_SENTINEL, leg);
      digest_init(target, leg);
      digest_init(retry, "joined-terminal-retry");
      join_ok(target, id, &bound, 32, leg);
      reset_result(&result, NULL);
      if (completion_first) complete_pair(target, &bound, &result, leg);
      Output before = bound;
      expect_rv("C_SessionCancel", leg,
                api->C_SessionCancel(target, CKF_DIGEST), CKR_OK);
      same_output("C_SessionCancel", leg, &bound, &before);
      refuse_complete(target, digest_name, CKR_OPERATION_NOT_INITIALIZED, &bound, leg);
      refuse_id(target, digest_name, CKR_OPERATION_NOT_INITIALIZED, &bound, leg);
      refuse_join(retry, digest_name, id, spare.bytes, 32,
                  completion_first ? CKR_ARGUMENTS_BAD : CKR_FUNCTION_CANCELED,
                  &spare, leg);
      if (completion_first)
        digest_bytes("C_SessionCancel", "joined-delivery-cannot-be-undone", &bound);
      else clean_output("C_SessionCancel", "joined-no-delivery", &bound, 32);
      clean_output("C_AsyncGetID", "joined-cancel-old-untouched", &old, 32);
    }
    fixture_close(retry);
    fixture_close(target);
    fixture_close(source);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: async_routed <module>\n");
    return 2;
  }
  if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) return 2;
  if (atexit(fixture_cleanup) != 0) return 2;
  fixture_configure(0);
  if (!discovery(fixture_load(argv[1]))) return 1;
  lifecycle("memory-before-init");
  fixture_initialize("memory");
  guards_and_names();
  attached_fields();
  synchronous_controls();
  occupied_and_classic_refusals();
  memory_no_store();
  cancellations();
  concurrent_completers();
  selector_pages();
  fixture_finalize("memory");
  lifecycle("memory-after-finalize");
  fixture_configure(1);
  lifecycle("sqlite-before-init");
  fixture_initialize("sqlite");
  sqlite_join_matrix();
  conservative_capacity();
  joined_cancellation();
  fixture_finalize("sqlite");
  lifecycle("sqlite-after-finalize");
  printf("async:summary/assertions/3.2 assertions=%u failures=%u\n", assertions, failures);
  return failures ? 1 : 0;
}

/* Fixture helpers are added only after the recorded missing-helper build. */
static void fixture_fail(const char *what) {
  fprintf(stderr, "async:fixture/%s/3.2 setup-failure\n", what);
  exit(2);
}

static void reset_output(Output *output, CK_ULONG capacity) {
  memset(output, 0xa5, sizeof(*output));
  output->length = capacity;
}

static void reset_result(Result *result, CK_BYTE *incoming) {
  memset(result, 0xa5, sizeof(*result));
  /* Use a real pointer representation even when the other public fields are
   * sentinels. The provider must ignore all incoming fields. */
  result->data.pValue = incoming;
}

static void fixture_configure(int sqlite) {
  if (!fixture_dir[0]) {
    if (mkdir("/tmp/haskoki-async-routing", 0700) != 0 && errno != EEXIST)
      fixture_fail("scratch-directory");
    char pattern[] = "/tmp/haskoki-async-routing/consumer-XXXXXX";
    if (!mkdtemp(pattern)) fixture_fail("temporary-directory");
    snprintf(fixture_dir, sizeof(fixture_dir), "%s", pattern);
  }
  char path[512];
  snprintf(path, sizeof(path), "%s/%s.toml",
           fixture_dir, sqlite ? "sqlite" : "memory");
  FILE *file = fopen(path, "w");
  if (!file) fixture_fail("config-open");
  int written = fprintf(file,
      "schema_version = 1\n"
      "profile = \"real-crypto\"\n"
      "[tokens]\n"
      "labels = [\"haskoki-demo\"]\n"
      "so_pins = [\"5678\"]\n"
      "user_pins = [\"1234\"]\n"
      "[storage]\n"
      "kind = \"%s\"\n", sqlite ? "sqlite" : "memory");
  int path_written = 0;
  if (sqlite) path_written = fprintf(file, "path = \"%s/jobs.db\"\n", fixture_dir);
  int engine_written = fprintf(file,
      "[engine]\n"
      "kind = \"openssl\"\n"
      "allow_synthetic_fallback = false\n"
      "private_library_context = true\n"
      "[trace]\n"
      "enabled = false\n");
  int closed = fclose(file);
  if (written < 0 || path_written < 0 || engine_written < 0 || closed != 0)
    fixture_fail("config-write");
  if (setenv("HASKOKI_CONFIG", path, 1) != 0) fixture_fail("config-environment");
}

static CK_C_GetInterface fixture_load(const char *path) {
  module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!module) {
    fprintf(stderr, "async:fixture/load/3.2 %s\n", dlerror());
    fixture_fail("load");
  }
  /* The only dlsym lookup in this consumer is public discovery. */
  CK_C_GetInterface get_interface = (CK_C_GetInterface)dlsym(module, "C_GetInterface");
  if (!get_interface) fixture_fail("discovery-symbol");
  return get_interface;
}

static void fixture_initialize(const char *leg) {
  if (!expect_rv("C_Initialize", leg, api->C_Initialize(NULL), CKR_OK))
    fixture_fail("initialize");
  initialized = 1;
  CK_ULONG count = 0;
  if (!expect_rv("C_GetSlotList", "token-present-count",
                 api->C_GetSlotList(CK_TRUE, NULL, &count), CKR_OK) ||
      count == 0 || count > 64)
    fixture_fail("slot-count");
  CK_SLOT_ID *slots = calloc((size_t)count, sizeof(*slots));
  if (!slots) fixture_fail("slot-allocation");
  CK_ULONG capacity = count;
  CK_RV code = api->C_GetSlotList(CK_TRUE, slots, &count);
  if (!expect_rv("C_GetSlotList", "token-present",
                 code, CKR_OK) || count == 0 || count > capacity) {
    free(slots);
    fixture_fail("slot-list");
  }
  static const char label[] = "haskoki-demo";
  unsigned matches = 0;
  for (CK_ULONG i = 0; i < count; ++i) {
    CK_TOKEN_INFO info;
    if (!expect_rv("C_GetTokenInfo", "discovered-token",
                   api->C_GetTokenInfo(slots[i], &info), CKR_OK)) {
      free(slots);
      fixture_fail("token-info");
    }
    int matches_label = memcmp(info.label, label, sizeof(label) - 1) == 0;
    for (size_t j = sizeof(label) - 1; j < sizeof(info.label); ++j)
      matches_label &= info.label[j] == ' ';
    if (matches_label) {
      home_slot = slots[i];
      ++matches;
      check("C_GetTokenInfo", "attached-async-capability",
            (info.flags & CKF_ASYNC_SESSION_SUPPORTED) != 0);
    }
  }
  free(slots);
  check("fixture", "unique-discovered-home-token", matches == 1);
  if (matches != 1) fixture_fail("home-token");
}

static CK_SESSION_HANDLE fixture_session(int async) {
  CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
  CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  if (async) flags |= CKF_ASYNC_SESSION;
  const char *leg = async ? "explicit-async" : "ordinary";
  if (!expect_rv("C_OpenSession", leg,
                 api->C_OpenSession(home_slot, flags, NULL, NULL, &session), CKR_OK))
    fixture_fail("open-session");
  CK_SESSION_INFO info;
  if (!expect_rv("C_GetSessionInfo", leg,
                 api->C_GetSessionInfo(session, &info), CKR_OK))
    fixture_fail("session-info");
  check("C_GetSessionInfo", leg,
        info.slotID == home_slot &&
        (info.flags & (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_ASYNC_SESSION)) == flags);
  return session;
}

static void fixture_close(CK_SESSION_HANDLE session) {
  if (!expect_rv("C_CloseSession", "cleanup", api->C_CloseSession(session), CKR_OK))
    fixture_fail("close-session");
}

static void fixture_finalize(const char *leg) {
  if (!expect_rv("C_Finalize", leg, api->C_Finalize(NULL), CKR_OK))
    fixture_fail("finalize");
  initialized = 0;
}

static void fixture_cleanup(void) {
  int failed = 0;
  /* Normal paths close sessions while their caller allocations remain live.
   * This is the setup-failure unwind; no fixture exits with running threads. */
  if (initialized && api) {
    if (api->C_Finalize(NULL) != CKR_OK) failed = 1;
    initialized = 0;
  }
  if (module) {
    if (dlclose(module) != 0) failed = 1;
    module = NULL;
  }
  if (fixture_dir[0]) {
    static const char *const files[] = {
      "memory.toml", "sqlite.toml", "jobs.db", "jobs.db-wal",
      "jobs.db-shm", "jobs.db-journal"
    };
    for (size_t i = 0; i < ARRAY_COUNT(files); ++i) {
      char path[512];
      snprintf(path, sizeof(path), "%s/%s", fixture_dir, files[i]);
      if (unlink(path) != 0 && errno != ENOENT) failed = 1;
    }
    if (rmdir(fixture_dir) != 0) failed = 1;
    fixture_dir[0] = '\0';
  }
  if (failed) {
    fputs("async:fixture/cleanup/3.2 setup-failure\n", stderr);
    _Exit(2);
  }
}

static CK_BYTE *fixture_pages(size_t *page_size) {
  long measured = sysconf(_SC_PAGESIZE);
  if (measured < 32) fixture_fail("page-size");
  *page_size = (size_t)measured;
  CK_BYTE *pages = mmap(NULL, 2 * *page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) fixture_fail("page-allocation");
  if (mprotect(pages + *page_size, *page_size, PROT_NONE) != 0) {
    munmap(pages, 2 * *page_size);
    fixture_fail("page-protection");
  }
  return pages;
}

static void fixture_unmap(CK_BYTE *pages, size_t page_size) {
  if (munmap(pages, 2 * page_size) != 0) fixture_fail("page-release");
}

static void fixture_race(Race *race) {
  if (pthread_mutex_init(&race->mutex, NULL) != 0)
    fixture_fail("race-mutex");
  if (pthread_cond_init(&race->ready, NULL) != 0) {
    pthread_mutex_destroy(&race->mutex);
    fixture_fail("race-condition");
  }
  if (pthread_barrier_init(&race->barrier, NULL, 3) != 0) {
    pthread_cond_destroy(&race->ready);
    pthread_mutex_destroy(&race->mutex);
    fixture_fail("race-barrier");
  }
  pthread_t threads[2];
  unsigned created = 0;
  int error = 0;
  for (; created < 2; ++created) {
    error = pthread_create(&threads[created], NULL, completer_thread,
                           &race->workers[created]);
    if (error != 0) break;
  }
  /* The condition gate lets a partially constructed fixture release and join
   * any created worker without stranding it at a three-party barrier. */
  pthread_mutex_lock(&race->mutex);
  race->start = error == 0 ? 1 : -1;
  pthread_cond_broadcast(&race->ready);
  pthread_mutex_unlock(&race->mutex);
  if (error == 0) {
    int status = pthread_barrier_wait(&race->barrier);
    if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) error = status;
  }
  for (unsigned i = 0; i < created; ++i) {
    int status = pthread_join(threads[i], NULL);
    if (status != 0) error = status;
  }
  int barrier_error = pthread_barrier_destroy(&race->barrier);
  int cond_error = pthread_cond_destroy(&race->ready);
  int mutex_error = pthread_mutex_destroy(&race->mutex);
  if (error || barrier_error || cond_error || mutex_error)
    fixture_fail("race-threads");
}
