/* tests/c/output_contracts.c — output-contract tests (standalone).
 *
 * Exercises cbits/native_bindings.c through the same contract the
 * Haskell planner implements: size-query/short/exact with canary
 * guards, null-versus-zero capacity, checked conversions, a partial
 * batch, a multi-handle transaction, and nested IV writeback.
 * Buffers that must stay untouched are canary-guarded on both sides
 * and pre-filled; any stray write fails the run.
 *
 * Compile with -I cbits. Part of scripts/test-c-output.sh.
 * Exit status 0 iff all checks pass.
 */

#include <stdio.h>
#include <string.h>

#include "native_bindings.h"

static int g_failures = 0;

#define EXPECT_EQ(actual, expected, what) do { \
    long _a = (long)(actual); \
    long _e = (long)(expected); \
    if (_a != _e) { \
      printf("FAIL: %s: got %ld, want %ld\n", (what), _a, _e); \
      g_failures++; \
    } \
  } while (0)

#define EXPECT_MEM_EQ(actual, expected, n, what) do { \
    if (memcmp((actual), (expected), (n)) != 0) { \
      printf("FAIL: %s: memory differs\n", (what)); \
      g_failures++; \
    } \
  } while (0)

#define CANARY 0xC3
#define FILLER 0xAA

/* One canary-guarded buffer: canary | body(cap) | canary. */
typedef struct {
  unsigned char lo;
  unsigned char body[64];
  unsigned char hi;
} guarded_t;

static void guarded_init(guarded_t *g, unsigned cap) {
  unsigned i;
  g->lo = CANARY;
  g->hi = CANARY;
  for (i = 0; i < sizeof(g->body); i++) {
    g->body[i] = FILLER;
  }
  (void)cap;
}

static void guarded_check(guarded_t *g, unsigned cap, const char *what) {
  char msg[128];
  unsigned i;
  snprintf(msg, sizeof(msg), "%s: low canary", what);
  EXPECT_EQ(g->lo, CANARY, msg);
  snprintf(msg, sizeof(msg), "%s: high canary", what);
  EXPECT_EQ(g->hi, CANARY, msg);
  for (i = cap; i < sizeof(g->body); i++) {
    if (g->body[i] != FILLER) {
      snprintf(msg, sizeof(msg), "%s: overshoot at %u", what, i);
      EXPECT_EQ(g->body[i], FILLER, msg);
      break;
    }
  }
}

/* ---------- case 1: sign-final query/short/exact ---------- */

static void case_sign_final(void) {
  static unsigned char sig[32];
  guarded_t g;
  haskoki_plan plan;
  unsigned i;
  int consumed = 0;
  int rc;
  printf("case: sign-final query/short/exact\n");
  for (i = 0; i < sizeof(sig); i++) {
    sig[i] = (unsigned char)(i + 1);
  }
  guarded_init(&g, 32);

  /* Size query: OK, required reported, nothing written. */
  plan = haskoki_plan_output(1, 0, 32);
  EXPECT_EQ(plan.rv, HASKOKI_OK, "query rv");
  EXPECT_EQ(plan.report, 32, "query report");
  EXPECT_EQ(plan.do_write, 0, "query do_write");
  guarded_check(&g, 32, "query");

  /* Short retry: BUFFER_TOO_SMALL, required reported, nothing written. */
  plan = haskoki_plan_output(0, 16, 32);
  EXPECT_EQ(plan.rv, HASKOKI_BUFFER_TOO_SMALL, "short rv");
  EXPECT_EQ(plan.report, 32, "short report");
  EXPECT_EQ(plan.do_write, 0, "short do_write");
  guarded_check(&g, 32, "short");

  /* Exact retry: OK, bytes land, input consumed exactly once. */
  plan = haskoki_plan_output(0, 32, 32);
  EXPECT_EQ(plan.rv, HASKOKI_OK, "exact rv");
  EXPECT_EQ(plan.report, 32, "exact report");
  EXPECT_EQ(plan.do_write, 1, "exact do_write");
  if (plan.do_write && plan.rv == HASKOKI_OK) {
    rc = haskoki_write_bytes(g.body, 32, sig, 32);
    EXPECT_EQ(rc, 0, "exact write rc");
    consumed++;
  }
  EXPECT_EQ(consumed, 1, "input consumed once");
  EXPECT_MEM_EQ(g.body, sig, 32, "exact payload");
  guarded_check(&g, 32, "exact");
}

/* ---------- case 2: null versus zero capacity ---------- */

static void case_null_vs_zero(void) {
  haskoki_plan plan;
  guarded_t g;
  int rc;
  printf("case: null versus zero capacity\n");
  guarded_init(&g, 0);

  plan = haskoki_plan_output(1, 0, 3);
  EXPECT_EQ(plan.rv, HASKOKI_OK, "null queries");
  EXPECT_EQ(plan.do_write, 0, "null writes nothing");

  /* Zero capacity with a nonzero requirement is a short buffer,
   * observably different from null. */
  plan = haskoki_plan_output(0, 0, 3);
  EXPECT_EQ(plan.rv, HASKOKI_BUFFER_TOO_SMALL, "zero-cap is short");
  EXPECT_EQ(plan.report, 3, "zero-cap reports required");
  EXPECT_EQ(plan.do_write, 0, "zero-cap writes nothing");

  /* Zero capacity only succeeds for an empty value. */
  plan = haskoki_plan_output(0, 0, 0);
  EXPECT_EQ(plan.rv, HASKOKI_OK, "zero-cap empty ok");
  EXPECT_EQ(plan.do_write, 1, "zero-cap empty writes");
  rc = haskoki_write_bytes(g.body, 0, (const unsigned char *)"", 0);
  EXPECT_EQ(rc, 0, "zero-cap empty write rc");
  guarded_check(&g, 0, "zero-cap empty");
}

/* ---------- case 3: checked conversions ---------- */

static void case_checked(void) {
  unsigned out32 = 0xDEADU;
  unsigned long total = 0xDEADUL;
  int rc;
  printf("case: checked conversions\n");

  rc = haskoki_u32_from_u64(0ULL, &out32);
  EXPECT_EQ(rc, 0, "u32 zero rc");
  EXPECT_EQ(out32, 0, "u32 zero");

  rc = haskoki_u32_from_u64(4294967295ULL, &out32);
  EXPECT_EQ(rc, 0, "u32 max rc");
  EXPECT_EQ(out32, 4294967295UL, "u32 max");

  out32 = 0xDEADU;
  rc = haskoki_u32_from_u64(4294967296ULL, &out32);
  EXPECT_EQ(rc, 1, "u32 overflow rc");
  EXPECT_EQ(out32, 0xDEADU, "u32 overflow untouched");

  rc = haskoki_u32_from_u64(18446744073709551615ULL, &out32);
  EXPECT_EQ(rc, 1, "u32 huge rc");

  rc = haskoki_u32_from_u64(7ULL, NULL);
  EXPECT_EQ(rc, 1, "u32 null out rc");

  rc = haskoki_checked_total(1UL, 2UL, &total);
  EXPECT_EQ(rc, 0, "total small rc");
  EXPECT_EQ(total, 3, "total small");

  total = 0xDEADUL;
  rc = haskoki_checked_total(0xFFFFFFFFFFFFFFFFUL, 1UL, &total);
  EXPECT_EQ(rc, 1, "total wrap rc");
  EXPECT_EQ(total, 0xDEADUL, "total wrap untouched");

  rc = haskoki_checked_total(1UL, 2UL, NULL);
  EXPECT_EQ(rc, 1, "total null out rc");
}

/* ---------- case 4: partial batch ---------- */

static void case_partial_batch(void) {
  guarded_t legs[3];
  static const unsigned char v0[5] = { 'v', 'a', 'l', 'u', 'e' };
  static const unsigned char v2[4] = { 'l', 'o', 'n', 'g' };
  haskoki_plan p0, p2;
  int rc;
  int i;
  printf("case: partial batch\n");
  for (i = 0; i < 3; i++) {
    guarded_init(&legs[i], 8);
  }

  /* Leg 0: exact write lands. Leg 1: sensitive failure, never
   * planned, canaries must hold. Leg 2: short buffer, required
   * reported, nothing written. */
  p0 = haskoki_plan_output(0, 8, 5);
  EXPECT_EQ(p0.rv, HASKOKI_OK, "leg0 rv");
  rc = haskoki_write_bytes(legs[0].body, 8, v0, 5);
  EXPECT_EQ(rc, 0, "leg0 write rc");
  EXPECT_MEM_EQ(legs[0].body, v0, 5, "leg0 payload");

  p2 = haskoki_plan_output(0, 1, 4);
  EXPECT_EQ(p2.rv, HASKOKI_BUFFER_TOO_SMALL, "leg2 rv");
  EXPECT_EQ(p2.report, 4, "leg2 report");
  EXPECT_EQ(p2.do_write, 0, "leg2 do_write");
  (void)v2;

  guarded_check(&legs[0], 8, "leg0");
  guarded_check(&legs[1], 8, "leg1 (failed, untouched)");
  guarded_check(&legs[2], 8, "leg2 (short, untouched)");
}

/* ---------- case 5: multi-handle transaction ---------- */

static void case_multi_handle(void) {
  /* Four 8-byte big-endian handles with canary words at both ends. */
  unsigned char area[2 + 4 * 8];
  unsigned i, h;
  int rc;
  printf("case: multi-handle transaction\n");
  memset(area, FILLER, sizeof(area));
  area[0] = CANARY;
  area[sizeof(area) - 1] = CANARY;
  for (h = 0; h < 4; h++) {
    unsigned char enc[8] = { 0, 0, 0, 0, 0, 0, 0, (unsigned char)(h + 1) };
    rc = haskoki_write_bytes(area + 1 + h * 8, 8, enc, 8);
    if (rc != 0) {
      printf("FAIL: handle %u write refused\n", h);
      g_failures++;
    }
  }
  for (h = 0; h < 4; h++) {
    char what[64];
    snprintf(what, sizeof(what), "handle %u tag", h);
    EXPECT_EQ(area[1 + h * 8 + 7], h + 1, what);
    for (i = 0; i < 7; i++) {
      if (area[1 + h * 8 + i] != 0) {
        snprintf(what, sizeof(what), "handle %u zero pad %u", h, i);
        EXPECT_EQ(area[1 + h * 8 + i], 0, what);
      }
    }
  }
  EXPECT_EQ(area[0], CANARY, "array low canary");
  EXPECT_EQ(area[sizeof(area) - 1], CANARY, "array high canary");

  /* A short leg refuses without touching its slot. */
  {
    unsigned char slot[8];
    unsigned char enc[8] = { 0, 0, 0, 0, 0, 0, 0, 9 };
    memset(slot, FILLER, sizeof(slot));
    rc = haskoki_write_bytes(slot, 4, enc, 8);
    EXPECT_EQ(rc, 1, "short handle refused");
    for (i = 0; i < 8; i++) {
      if (slot[i] != FILLER) {
        printf("FAIL: short handle slot touched at %u\n", i);
        g_failures++;
        break;
      }
    }
  }
}

/* ---------- case 6: nested IV writeback ---------- */

typedef struct {
  unsigned long pre;
  haskoki_gcm_params params;
  unsigned long post;
} guarded_params_t;

static void case_iv_writeback(void) {
  guarded_params_t g;
  static const unsigned char iv[16] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
  };
  static const unsigned char short_iv[12] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
  };
  int rc;
  printf("case: nested IV writeback\n");
  g.pre = 0xC3C3C3C3UL;
  g.post = 0xC3C3C3C3UL;
  memset(g.params.iv, FILLER, sizeof(g.params.iv));
  g.params.iv_len = 0;

  rc = haskoki_writeback_iv(&g.params, iv, 16);
  EXPECT_EQ(rc, 0, "writeback rc");
  EXPECT_MEM_EQ(g.params.iv, iv, 16, "iv landed");
  EXPECT_EQ(g.params.iv_len, 16, "iv_len set");
  EXPECT_EQ(g.pre, 0xC3C3C3C3UL, "struct low canary");
  EXPECT_EQ(g.post, 0xC3C3C3C3UL, "struct high canary");

  /* Wrong-length IV refuses and leaves the struct untouched. */
  memset(g.params.iv, FILLER, sizeof(g.params.iv));
  g.params.iv_len = 77;
  rc = haskoki_writeback_iv(&g.params, short_iv, 12);
  EXPECT_EQ(rc, 1, "short iv refused");
  EXPECT_EQ(g.params.iv_len, 77, "iv_len untouched");
  {
    unsigned i;
    for (i = 0; i < sizeof(g.params.iv); i++) {
      if (g.params.iv[i] != FILLER) {
        printf("FAIL: refused writeback touched byte %u\n", i);
        g_failures++;
        break;
      }
    }
  }
  rc = haskoki_writeback_iv(NULL, iv, 16);
  EXPECT_EQ(rc, 1, "null params refused");
  rc = haskoki_writeback_iv(&g.params, NULL, 16);
  EXPECT_EQ(rc, 1, "null iv refused");
}

int main(void) {
  case_sign_final();
  case_null_vs_zero();
  case_checked();
  case_partial_batch();
  case_multi_handle();
  case_iv_writeback();
  if (g_failures == 0) {
    printf("PASS: output_contracts (query/short/exact + batch + writeback)\n");
    return 0;
  }
  printf("FAIL: output_contracts (%d failures)\n", g_failures);
  return 1;
}
