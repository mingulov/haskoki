/* tests/journeys/native/token_fixture.c — holder and same-instance busy fixture.
 *
 * Journeys helper (not a consumer scenario): drives exactly the two
 * busy-case shapes the installed runs need, against the module at
 * argv[1]:
 *   - hold: Initialize, open an RW session on slot 0, write the
 *     ready file, block on stdin until EOF, then close and finalize.
 *     Prints "FIXTURE hold ready" and "FIXTURE hold released".
 *   - init-busy: Initialize, open an RW session, snapshot the token
 *     label and the visible object count, attempt C_InitToken (which
 *     must refuse CKR_SESSION_EXISTS while the session is open),
 *     then prove the label and the count are unchanged. Prints the
 *     observed CKR name and "FIXTURE init-busy unchanged".
 *
 * This TU includes ONLY the pinned vendor headers plus libc headers;
 * it never consumes provider-generated artifacts. The function table
 * comes from dlsym("C_GetFunctionList"): the module exports no
 * direct C_* symbols.
 *
 * Build (journeys driver --build-native):
 *   cc -std=c11 -Wall -Wextra -Werror -Ispec/vendor -o DIR/token_fixture \
 *     tests/journeys/native/token_fixture.c -ldl
 * Usage:
 *   token_fixture <libhaskoki.so> hold <ready-file>
 *   token_fixture <libhaskoki.so> init-busy
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FIXTURE_CKR(name) case name: return #name;

static const char *ckr_name(CK_RV rv) {
  switch (rv) {
    FIXTURE_CKR(CKR_OK)
    FIXTURE_CKR(CKR_CANCEL)
    FIXTURE_CKR(CKR_HOST_MEMORY)
    FIXTURE_CKR(CKR_SLOT_ID_INVALID)
    FIXTURE_CKR(CKR_GENERAL_ERROR)
    FIXTURE_CKR(CKR_FUNCTION_FAILED)
    FIXTURE_CKR(CKR_ARGUMENTS_BAD)
    FIXTURE_CKR(CKR_NO_EVENT)
    FIXTURE_CKR(CKR_NEED_TO_CREATE_THREADS)
    FIXTURE_CKR(CKR_CANT_LOCK)
    FIXTURE_CKR(CKR_ATTRIBUTE_READ_ONLY)
    FIXTURE_CKR(CKR_ATTRIBUTE_SENSITIVE)
    FIXTURE_CKR(CKR_ATTRIBUTE_TYPE_INVALID)
    FIXTURE_CKR(CKR_ATTRIBUTE_VALUE_INVALID)
    FIXTURE_CKR(CKR_ACTION_PROHIBITED)
    FIXTURE_CKR(CKR_DATA_INVALID)
    FIXTURE_CKR(CKR_DATA_LEN_RANGE)
    FIXTURE_CKR(CKR_DEVICE_ERROR)
    FIXTURE_CKR(CKR_DEVICE_MEMORY)
    FIXTURE_CKR(CKR_DEVICE_REMOVED)
    FIXTURE_CKR(CKR_ENCRYPTED_DATA_INVALID)
    FIXTURE_CKR(CKR_ENCRYPTED_DATA_LEN_RANGE)
    FIXTURE_CKR(CKR_FUNCTION_CANCELED)
    FIXTURE_CKR(CKR_FUNCTION_NOT_PARALLEL)
    FIXTURE_CKR(CKR_FUNCTION_NOT_SUPPORTED)
    FIXTURE_CKR(CKR_KEY_HANDLE_INVALID)
    FIXTURE_CKR(CKR_KEY_SIZE_RANGE)
    FIXTURE_CKR(CKR_KEY_TYPE_INCONSISTENT)
    FIXTURE_CKR(CKR_KEY_NOT_NEEDED)
    FIXTURE_CKR(CKR_KEY_CHANGED)
    FIXTURE_CKR(CKR_KEY_NEEDED)
    FIXTURE_CKR(CKR_KEY_INDIGESTIBLE)
    FIXTURE_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED)
    FIXTURE_CKR(CKR_KEY_NOT_WRAPPABLE)
    FIXTURE_CKR(CKR_KEY_UNEXTRACTABLE)
    FIXTURE_CKR(CKR_MECHANISM_INVALID)
    FIXTURE_CKR(CKR_MECHANISM_PARAM_INVALID)
    FIXTURE_CKR(CKR_OBJECT_HANDLE_INVALID)
    FIXTURE_CKR(CKR_OPERATION_ACTIVE)
    FIXTURE_CKR(CKR_OPERATION_NOT_INITIALIZED)
    FIXTURE_CKR(CKR_PIN_INCORRECT)
    FIXTURE_CKR(CKR_PIN_INVALID)
    FIXTURE_CKR(CKR_PIN_LEN_RANGE)
    FIXTURE_CKR(CKR_PIN_EXPIRED)
    FIXTURE_CKR(CKR_PIN_LOCKED)
    FIXTURE_CKR(CKR_SESSION_CLOSED)
    FIXTURE_CKR(CKR_SESSION_COUNT)
    FIXTURE_CKR(CKR_SESSION_HANDLE_INVALID)
    FIXTURE_CKR(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
    FIXTURE_CKR(CKR_SESSION_READ_ONLY)
    FIXTURE_CKR(CKR_SESSION_EXISTS)
    FIXTURE_CKR(CKR_SESSION_READ_ONLY_EXISTS)
    FIXTURE_CKR(CKR_SESSION_READ_WRITE_SO_EXISTS)
    FIXTURE_CKR(CKR_SIGNATURE_INVALID)
    FIXTURE_CKR(CKR_SIGNATURE_LEN_RANGE)
    FIXTURE_CKR(CKR_TEMPLATE_INCOMPLETE)
    FIXTURE_CKR(CKR_TEMPLATE_INCONSISTENT)
    FIXTURE_CKR(CKR_TOKEN_NOT_PRESENT)
    FIXTURE_CKR(CKR_TOKEN_NOT_RECOGNIZED)
    FIXTURE_CKR(CKR_TOKEN_WRITE_PROTECTED)
    FIXTURE_CKR(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    FIXTURE_CKR(CKR_UNWRAPPING_KEY_SIZE_RANGE)
    FIXTURE_CKR(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
    FIXTURE_CKR(CKR_USER_ALREADY_LOGGED_IN)
    FIXTURE_CKR(CKR_USER_NOT_LOGGED_IN)
    FIXTURE_CKR(CKR_USER_PIN_NOT_INITIALIZED)
    FIXTURE_CKR(CKR_USER_TYPE_INVALID)
    FIXTURE_CKR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
    FIXTURE_CKR(CKR_USER_TOO_MANY_TYPES)
    FIXTURE_CKR(CKR_WRAPPING_KEY_HANDLE_INVALID)
    FIXTURE_CKR(CKR_WRAPPING_KEY_SIZE_RANGE)
    FIXTURE_CKR(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
    FIXTURE_CKR(CKR_RANDOM_SEED_NOT_SUPPORTED)
    FIXTURE_CKR(CKR_RANDOM_NO_RNG)
    FIXTURE_CKR(CKR_DOMAIN_PARAMS_INVALID)
    FIXTURE_CKR(CKR_CURVE_NOT_SUPPORTED)
    FIXTURE_CKR(CKR_BUFFER_TOO_SMALL)
    FIXTURE_CKR(CKR_CRYPTOKI_NOT_INITIALIZED)
    FIXTURE_CKR(CKR_CRYPTOKI_ALREADY_INITIALIZED)
    FIXTURE_CKR(CKR_MUTEX_BAD)
    FIXTURE_CKR(CKR_MUTEX_NOT_LOCKED)
  default:
    return "CKR_UNKNOWN";
  }
}

static CK_FUNCTION_LIST_PTR open_module(const char *path, void **handle_out) {
  void *handle;
  CK_C_GetFunctionList get_list;
  CK_FUNCTION_LIST_PTR api = NULL_PTR;
  CK_RV rv;
  handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "fixture: dlopen failed: %s\n", dlerror());
    return NULL_PTR;
  }
  get_list = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (!get_list) {
    fprintf(stderr, "fixture: C_GetFunctionList missing: %s\n", dlerror());
    dlclose(handle);
    return NULL_PTR;
  }
  rv = get_list(&api);
  if (rv != CKR_OK || !api) {
    fprintf(stderr, "fixture: C_GetFunctionList refused: %s\n", ckr_name(rv));
    dlclose(handle);
    return NULL_PTR;
  }
  *handle_out = handle;
  return api;
}

static void make_label32(const char *text, CK_UTF8CHAR out[32]) {
  size_t n, i;
  memset(out, ' ', 32);
  n = strlen(text);
  if (n > 32) n = 32;
  for (i = 0; i < n; i++) out[i] = (CK_UTF8CHAR)text[i];
}

static CK_RV token_label(CK_FUNCTION_LIST_PTR api, CK_UTF8CHAR out[32]) {
  CK_TOKEN_INFO info;
  CK_RV rv = api->C_GetTokenInfo(0, &info);
  if (rv == CKR_OK) memcpy(out, info.label, 32);
  return rv;
}

static CK_RV count_objects(CK_FUNCTION_LIST_PTR api, CK_SESSION_HANDLE sess,
                           CK_ULONG *out) {
  CK_OBJECT_HANDLE buf[64];
  CK_ULONG chunk = 0, total = 0;
  CK_RV rv, fin;
  rv = api->C_FindObjectsInit(sess, NULL_PTR, 0);
  if (rv != CKR_OK) return rv;
  for (;;) {
    rv = api->C_FindObjects(sess, buf, 64, &chunk);
    if (rv != CKR_OK || chunk == 0) break;
    total += chunk;
  }
  fin = api->C_FindObjectsFinal(sess);
  if (rv == CKR_OK) rv = fin;
  if (rv == CKR_OK) *out = total;
  return rv;
}

static int do_hold(CK_FUNCTION_LIST_PTR api, const char *ready_path) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  int fd;
  ssize_t n;
  char buf[256];
  static const char ready_mark[] = "ready\n";
  rv = api->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: hold C_Initialize refused: %s\n", ckr_name(rv));
    return 1;
  }
  rv = api->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: hold C_OpenSession refused: %s\n", ckr_name(rv));
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  fd = open(ready_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    fprintf(stderr, "fixture: hold cannot write %s: %s\n", ready_path,
            strerror(errno));
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  if (write(fd, ready_mark, sizeof(ready_mark) - 1)
      != (ssize_t)(sizeof(ready_mark) - 1)) {
    fprintf(stderr, "fixture: hold cannot write %s: %s\n", ready_path,
            strerror(errno));
    close(fd);
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  close(fd);
  printf("FIXTURE hold ready\n");
  fflush(stdout);
  for (;;) {
    n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n == 0) break;
    if (n < 0) {
      if (errno == EINTR) continue;
      fprintf(stderr, "fixture: hold stdin refused: %s\n", strerror(errno));
      api->C_CloseSession(sess);
      api->C_Finalize(NULL_PTR);
      return 1;
    }
  }
  rv = api->C_CloseSession(sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: hold C_CloseSession refused: %s\n", ckr_name(rv));
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = api->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: hold C_Finalize refused: %s\n", ckr_name(rv));
    return 1;
  }
  printf("FIXTURE hold released\n");
  return 0;
}

static int do_init_busy(CK_FUNCTION_LIST_PTR api) {
  CK_RV rv, init_rv;
  CK_SESSION_HANDLE sess = 0;
  CK_UTF8CHAR label1[32], label2[32], fresh[32];
  CK_ULONG n1 = 0, n2 = 0;
  rv = api->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_Initialize refused: %s\n",
            ckr_name(rv));
    return 1;
  }
  rv = api->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_OpenSession refused: %s\n",
            ckr_name(rv));
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = token_label(api, label1);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_GetTokenInfo refused: %s\n",
            ckr_name(rv));
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = count_objects(api, sess, &n1);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_FindObjects refused: %s\n",
            ckr_name(rv));
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  make_label32("haskoki-demo", fresh);
  init_rv = api->C_InitToken(0, (CK_UTF8CHAR_PTR)"5678", 4, fresh);
  /* The quotes make the CKR name a whole token for the refusal rule. */
  printf("FIXTURE init-busy rv=\"%s\"\n", ckr_name(init_rv));
  fflush(stdout);
  rv = token_label(api, label2);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy second C_GetTokenInfo refused: %s\n",
            ckr_name(rv));
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = count_objects(api, sess, &n2);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy second C_FindObjects refused: %s\n",
            ckr_name(rv));
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  if (init_rv != CKR_SESSION_EXISTS) {
    fprintf(stderr, "fixture: init-busy refusal %s (0x%lx), want "
                    "CKR_SESSION_EXISTS\n",
            ckr_name(init_rv), (unsigned long)init_rv);
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  if (memcmp(label1, label2, 32) != 0) {
    fprintf(stderr, "fixture: init-busy label changed\n");
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  if (n1 != n2) {
    fprintf(stderr, "fixture: init-busy object count %lu -> %lu\n",
            (unsigned long)n1, (unsigned long)n2);
    api->C_CloseSession(sess);
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = api->C_CloseSession(sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_CloseSession refused: %s\n",
            ckr_name(rv));
    api->C_Finalize(NULL_PTR);
    return 1;
  }
  rv = api->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr, "fixture: init-busy C_Finalize refused: %s\n", ckr_name(rv));
    return 1;
  }
  printf("FIXTURE init-busy unchanged\n");
  return 0;
}

int main(int argc, char **argv) {
  void *handle = NULL;
  CK_FUNCTION_LIST_PTR api;
  int rc;
  if (argc == 4 && strcmp(argv[2], "hold") == 0) {
    api = open_module(argv[1], &handle);
    if (!api) return 2;
    rc = do_hold(api, argv[3]);
    dlclose(handle);
    return rc;
  }
  if (argc == 3 && strcmp(argv[2], "init-busy") == 0) {
    api = open_module(argv[1], &handle);
    if (!api) return 2;
    rc = do_init_busy(api);
    dlclose(handle);
    return rc;
  }
  fprintf(stderr, "usage: %s <libhaskoki.so> hold <ready-file>\n", argv[0]);
  fprintf(stderr, "       %s <libhaskoki.so> init-busy\n", argv[0]);
  return 2;
}
