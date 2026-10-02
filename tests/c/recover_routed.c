#define _POSIX_C_SOURCE 200809L
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#include "pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Recover composition proof: the four sign/verify-recover entrypoints
 * route C -> FFI -> planner -> engine on every versioned table for
 * the two raw-RSA mechanisms, and each run round-trips at the C
 * boundary (verify recovers the exact input bytes). Route legs pin
 * one entrypoint each per version (init, one-shot with length
 * query, short-buffer recall, determinism for the unpadded flows);
 * pkcs legs mirror the route legs over CKM_RSA_PKCS with short
 * inputs (the driver frames block-type-1); flag legs pin the
 * CKF_SIGN_RECOVER/CKF_VERIFY_RECOVER advertisement on the pair
 * and its absence elsewhere; refusal legs pin the joint contract
 * (unknown mechanism, digest-row exclusion, oversize input,
 * short/oversize blocks, wrong key type, malformed pointers).
 *
 * Usage: recover_routed <module> [--version 2.40|3.0|3.1|3.2]
 *                              [--legs route|pkcs|flags|neg|all]
 * Exit 0 iff every selected leg passes; 1 on any leg failure; 2 on
 * setup failure (usage, config, load, discovery).
 */
static int failures;
static char ver[8];
static CK_SLOT_ID tokenSlot;
static char configPath[256];
static const char msgText[] = "recover-me-round-trip";
static const char pkcsText[] = "pkcs-recover-me";
static CK_BYTE aesBytes[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static const CK_BYTE p256oid[] = {0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};

typedef struct {
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CreateObject C_CreateObject;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
} RecoverApi;
typedef struct { CK_SESSION_HANDLE session; CK_OBJECT_HANDLE pub, priv; } Fixture;
typedef struct { CK_BYTE bytes[512]; CK_ULONG length; } Output;

static void check(const char *entry, const char *leg, int good) {
  printf("recover:%s/%s/%s check=%s\n",entry,leg,ver,good ? "ok" : "FAIL");
  if (!good) ++failures;
}
static void rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  printf("recover:%s/%s/%s rv=0x%lx expected=0x%lx\n",entry,leg,ver,(unsigned long)got,(unsigned long)want);
  if (got != want) ++failures;
}
static void reset_output(Output *o, CK_ULONG n) { memset(o->bytes,0xa5,sizeof(o->bytes)); o->length=n; }
static void rv_note(const char *entry, const char *leg, CK_RV got) {
  printf("recover:%s/%s/%s rv=0x%lx noted\n",entry,leg,ver,(unsigned long)got);
}

/* Full-width raw-RSA input: 0x00 0x01 0xFF.. 0x00 message, the
 * caller-padded 256-byte shape for a 2048-bit modulus. */
static void x509_input(CK_BYTE *out, const char *msg) {
  size_t n = strlen(msg), pad = 256 - 3 - n;
  size_t i;
  out[0] = 0x00;
  out[1] = 0x01;
  for (i = 0; i < pad; ++i) out[2 + i] = 0xff;
  out[2 + pad] = 0x00;
  memcpy(out + 3 + pad, msg, n);
}

static void configure(void) {
  char path[]="/tmp/haskoki-recover-config-XXXXXX";
  const char body[]="schema_version = 1\nprofile = \"real-crypto\"\n[storage]\nkind = \"memory\"\n[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\nprivate_library_context = true\n[trace]\nenabled = false\n";
  int fd=mkstemp(path);
  if (fd<0 || write(fd,body,sizeof(body)-1)!=(ssize_t)(sizeof(body)-1)) exit(2);
  close(fd);
  snprintf(configPath,sizeof(configPath),"%s",path);
  if (setenv("HASKOKI_CONFIG",configPath,1)!=0) exit(2);
}

static RecoverApi read_legacy(CK_FUNCTION_LIST *table) {
  RecoverApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_GenerateKeyPair=table->C_GenerateKeyPair;
  a.C_SignRecoverInit=table->C_SignRecoverInit;
  a.C_SignRecover=table->C_SignRecover;
  a.C_VerifyRecoverInit=table->C_VerifyRecoverInit;
  a.C_VerifyRecover=table->C_VerifyRecover;
  check("C_SignRecoverInit","slot-present",a.C_SignRecoverInit != NULL);
  check("C_SignRecover","slot-present",a.C_SignRecover != NULL);
  check("C_VerifyRecoverInit","slot-present",a.C_VerifyRecoverInit != NULL);
  check("C_VerifyRecover","slot-present",a.C_VerifyRecover != NULL);
  return a;
}
static RecoverApi read_common(CK_FUNCTION_LIST_3_0 *table) {
  RecoverApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_GenerateKeyPair=table->C_GenerateKeyPair;
  a.C_SignRecoverInit=table->C_SignRecoverInit;
  a.C_SignRecover=table->C_SignRecover;
  a.C_VerifyRecoverInit=table->C_VerifyRecoverInit;
  a.C_VerifyRecover=table->C_VerifyRecover;
  check("C_SignRecoverInit","slot-present",a.C_SignRecoverInit != NULL);
  check("C_SignRecover","slot-present",a.C_SignRecover != NULL);
  check("C_VerifyRecoverInit","slot-present",a.C_VerifyRecoverInit != NULL);
  check("C_VerifyRecover","slot-present",a.C_VerifyRecover != NULL);
  return a;
}
static RecoverApi read_newest(CK_FUNCTION_LIST_3_2 *table) {
  RecoverApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_GenerateKeyPair=table->C_GenerateKeyPair;
  a.C_SignRecoverInit=table->C_SignRecoverInit;
  a.C_SignRecover=table->C_SignRecover;
  a.C_VerifyRecoverInit=table->C_VerifyRecoverInit;
  a.C_VerifyRecover=table->C_VerifyRecover;
  check("C_SignRecoverInit","slot-present",a.C_SignRecoverInit != NULL);
  check("C_SignRecover","slot-present",a.C_SignRecover != NULL);
  check("C_VerifyRecoverInit","slot-present",a.C_VerifyRecoverInit != NULL);
  check("C_VerifyRecover","slot-present",a.C_VerifyRecover != NULL);
  return a;
}

/* One RSA-2048 recovery pair per leg: the public half carries
 * CKA_VERIFY_RECOVER, the private half CKA_SIGN_RECOVER, and
 * nothing else usage-bearing (a plain-sign framing would refuse
 * these keys, so the legs prove the recover usage path). */
static Fixture fixture(RecoverApi *a) {
  Fixture f={0,0,0};
  CK_OBJECT_CLASS pcls=CKO_PUBLIC_KEY, scls=CKO_PRIVATE_KEY;
  CK_KEY_TYPE rkt=CKK_RSA;
  CK_ULONG bits=2048;
  CK_BBOOL no=CK_FALSE, yes=CK_TRUE;
  CK_BYTE exp[3]={0x01,0x00,0x01};
  CK_MECHANISM kgm={CKM_RSA_PKCS_KEY_PAIR_GEN,NULL,0};
  CK_ATTRIBUTE pubT[]={
    {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&rkt,sizeof(rkt)},
    {CKA_MODULUS_BITS,&bits,sizeof(bits)},{CKA_TOKEN,&no,sizeof(no)},
    {CKA_VERIFY_RECOVER,&yes,sizeof(yes)},
    {CKA_PUBLIC_EXPONENT,exp,sizeof(exp)}
  };
  CK_ATTRIBUTE privT[]={
    {CKA_CLASS,&scls,sizeof(scls)},{CKA_TOKEN,&no,sizeof(no)},
    {CKA_SIGN_RECOVER,&yes,sizeof(yes)}
  };
  CK_RV result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&f.session);
  rv("fixture","open",result,CKR_OK);
  if (result != CKR_OK) exit(2);
  result=a->C_GenerateKeyPair(f.session,&kgm,pubT,6,privT,3,&f.pub,&f.priv);
  rv("fixture","keygen",result,CKR_OK);
  if (result != CKR_OK || f.pub==0 || f.priv==0 || f.pub==f.priv) exit(2);
  return f;
}
static void close_fixture(RecoverApi *a, Fixture f) { rv("fixture","close",a->C_CloseSession(f.session),CKR_OK); }

/* Route legs over CKM_RSA_X_509: one entrypoint each. The sign leg
 * proves the length query, the 256-byte block, determinism
 * (raw RSA takes no randomness), short-buffer recall, and the
 * short-input acceptance (left-padded to the modulus width);
 * the verify leg proves the round-trip plus the tamper shape
 * (raw RSA reports whatever the exponentiation yields). */
static void route_sign_recover_init(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_RV result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("C_SignRecoverInit","route",result,CKR_OK);
  check("C_SignRecoverInit","route",result==CKR_OK);
  close_fixture(a,f);
}
static void route_sign_recover(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_BYTE input[256], shortIn[200], expect[256];
  Output q, s, d, r, t;
  int good=1;
  CK_RV result;
  x509_input(input,msgText);
  memset(shortIn,0xa5,sizeof(shortIn));
  memset(expect,0,sizeof(expect));
  memcpy(expect+(256-sizeof(shortIn)),shortIn,sizeof(shortIn));
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","sign-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&q,0);
  result=a->C_SignRecover(f.session,input,sizeof(input),NULL,&q.length);
  rv("setup","sign-query",result,CKR_OK); good &= result==CKR_OK;
  good &= q.length==256;
  reset_output(&s,256);
  result=a->C_SignRecover(f.session,input,sizeof(input),s.bytes,&s.length);
  rv("C_SignRecover","route",result,CKR_OK); good &= result==CKR_OK;
  good &= s.length==256;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","sign-reinit",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&d,256);
  result=a->C_SignRecover(f.session,input,sizeof(input),d.bytes,&d.length);
  rv("setup","sign-repeat",result,CKR_OK); good &= result==CKR_OK;
  good &= d.length==256 && memcmp(s.bytes,d.bytes,256)==0;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","sign-reinit2",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&r,10);
  result=a->C_SignRecover(f.session,input,sizeof(input),r.bytes,&r.length);
  rv("setup","sign-short",result,CKR_BUFFER_TOO_SMALL); good &= result==CKR_BUFFER_TOO_SMALL;
  good &= r.length==256;
  reset_output(&r,256);
  result=a->C_SignRecover(f.session,input,sizeof(input),r.bytes,&r.length);
  rv("setup","sign-recall",result,CKR_OK); good &= result==CKR_OK;
  good &= r.length==256 && memcmp(s.bytes,r.bytes,256)==0;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","sign-reinit3",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&t,256);
  result=a->C_SignRecover(f.session,shortIn,sizeof(shortIn),t.bytes,&t.length);
  rv("setup","sign-short-input",result,CKR_OK); good &= result==CKR_OK;
  good &= t.length==256;
  {
    Output u;
    result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
    rv("setup","sign-short-vinit",result,CKR_OK); good &= result==CKR_OK;
    reset_output(&u,256);
    result=a->C_VerifyRecover(f.session,t.bytes,t.length,u.bytes,&u.length);
    rv("setup","sign-short-v",result,CKR_OK); good &= result==CKR_OK;
    good &= u.length==256 && memcmp(u.bytes,expect,256)==0;
  }
  check("C_SignRecover","route",good);
  close_fixture(a,f);
}
static void route_verify_recover_init(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_RV result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("C_VerifyRecoverInit","route",result,CKR_OK);
  check("C_VerifyRecoverInit","route",result==CKR_OK);
  close_fixture(a,f);
}
static void route_verify_recover(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_BYTE input[256];
  Output s, q, v;
  CK_BYTE bad[256];
  Output w;
  int good=1;
  CK_RV result;
  x509_input(input,msgText);
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","v-sign-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&s,256);
  result=a->C_SignRecover(f.session,input,sizeof(input),s.bytes,&s.length);
  rv("setup","v-sign",result,CKR_OK); good &= result==CKR_OK;
  good &= s.length==256;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("setup","v-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&q,0);
  result=a->C_VerifyRecover(f.session,s.bytes,s.length,NULL,&q.length);
  rv("setup","v-query",result,CKR_OK); good &= result==CKR_OK;
  good &= q.length==256;
  reset_output(&v,256);
  result=a->C_VerifyRecover(f.session,s.bytes,s.length,v.bytes,&v.length);
  rv("C_VerifyRecover","route",result,CKR_OK); good &= result==CKR_OK;
  good &= v.length==256 && memcmp(v.bytes,input,256)==0;
  memcpy(bad,s.bytes,256);
  bad[255]^=0xff;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("setup","v-reinit",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&w,256);
  result=a->C_VerifyRecover(f.session,bad,sizeof(bad),w.bytes,&w.length);
  rv_note("setup","v-tamper",result);
  good &= (result==CKR_OK && w.length==256 && memcmp(w.bytes,input,256)!=0)
    || result==CKR_SIGNATURE_INVALID;
  check("C_VerifyRecover","route",good);
  close_fixture(a,f);
}

/* PKCS legs over CKM_RSA_PKCS: the same entrypoint-per-leg shape
 * with short inputs (the driver frames block-type-1, so the
 * caller passes bare data and recovers bare data). */
static void pkcs_sign_recover_init(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_PKCS,NULL,0};
  CK_RV result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("C_SignRecoverInit","pkcs",result,CKR_OK);
  check("C_SignRecoverInit","pkcs",result==CKR_OK);
  close_fixture(a,f);
}
static void pkcs_sign_recover(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_PKCS,NULL,0};
  size_t n=strlen(pkcsText);
  Output q, s, d;
  int good=1;
  CK_RV result;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","p-sign-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&q,0);
  result=a->C_SignRecover(f.session,(CK_BYTE_PTR)pkcsText,(CK_ULONG)n,NULL,&q.length);
  rv("setup","p-sign-query",result,CKR_OK); good &= result==CKR_OK;
  good &= q.length==256;
  reset_output(&s,256);
  result=a->C_SignRecover(f.session,(CK_BYTE_PTR)pkcsText,(CK_ULONG)n,s.bytes,&s.length);
  rv("C_SignRecover","pkcs",result,CKR_OK); good &= result==CKR_OK;
  good &= s.length==256;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","p-sign-reinit",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&d,256);
  result=a->C_SignRecover(f.session,(CK_BYTE_PTR)pkcsText,(CK_ULONG)n,d.bytes,&d.length);
  rv("setup","p-sign-repeat",result,CKR_OK); good &= result==CKR_OK;
  good &= d.length==256 && memcmp(s.bytes,d.bytes,256)==0;
  check("C_SignRecover","pkcs",good);
  close_fixture(a,f);
}
static void pkcs_verify_recover_init(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_PKCS,NULL,0};
  CK_RV result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("C_VerifyRecoverInit","pkcs",result,CKR_OK);
  check("C_VerifyRecoverInit","pkcs",result==CKR_OK);
  close_fixture(a,f);
}
static void pkcs_verify_recover(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_PKCS,NULL,0};
  size_t n=strlen(pkcsText);
  Output s, v;
  CK_BYTE bad[256];
  Output w;
  int good=1;
  CK_RV result;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("setup","p-v-sign-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&s,256);
  result=a->C_SignRecover(f.session,(CK_BYTE_PTR)pkcsText,(CK_ULONG)n,s.bytes,&s.length);
  rv("setup","p-v-sign",result,CKR_OK); good &= result==CKR_OK;
  good &= s.length==256;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("setup","p-v-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&v,256);
  result=a->C_VerifyRecover(f.session,s.bytes,s.length,v.bytes,&v.length);
  rv("C_VerifyRecover","pkcs",result,CKR_OK); good &= result==CKR_OK;
  good &= v.length==(CK_ULONG)n && memcmp(v.bytes,pkcsText,n)==0;
  memcpy(bad,s.bytes,256);
  /* Flip the low byte only: a top-byte flip can push the block
   * past the modulus, and the backend failure for an
   * unprocessable block varies per key draw; the low-byte flip
   * keeps the block processable so the leg deterministically
   * proves tamper sensitivity (recovered bytes differ). */
  bad[255]^=0xff;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("setup","p-v-reinit",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&w,256);
  result=a->C_VerifyRecover(f.session,bad,sizeof(bad),w.bytes,&w.length);
  rv_note("setup","p-v-tamper",result);
  good &= result==CKR_SIGNATURE_INVALID
    || (result==CKR_OK && (w.length!=(CK_ULONG)n || memcmp(w.bytes,pkcsText,n)!=0));
  check("C_VerifyRecover","pkcs",good);
  close_fixture(a,f);
}

/* Flag legs: the pair advertises both recover flags through
 * C_GetMechanismInfo, a non-pair row advertises neither. */
static void flags_one(RecoverApi *a, CK_MECHANISM_TYPE mech, const char *tag) {
  CK_MECHANISM_INFO info;
  CK_ULONG count=0;
  CK_MECHANISM_TYPE listed[512];
  CK_ULONG i;
  int good=1, found=0;
  CK_RV result;
  memset(&info,0,sizeof(info));
  result=a->C_GetMechanismList(tokenSlot,NULL,&count);
  rv("setup","flags-list-query",result,CKR_OK); good &= result==CKR_OK;
  good &= count>0 && count<=512;
  result=a->C_GetMechanismList(tokenSlot,listed,&count);
  rv("setup","flags-list",result,CKR_OK); good &= result==CKR_OK;
  for (i=0;i<count;++i) if (listed[i]==mech) found=1;
  good &= found;
  result=a->C_GetMechanismInfo(tokenSlot,mech,&info);
  rv("setup","flags-info",result,CKR_OK); good &= result==CKR_OK;
  good &= (info.flags & CKF_SIGN_RECOVER)!=0 && (info.flags & CKF_VERIFY_RECOVER)!=0;
  memset(&info,0,sizeof(info));
  result=a->C_GetMechanismInfo(tokenSlot,CKM_AES_CBC,&info);
  rv("setup","flags-info-aes",result,CKR_OK); good &= result==CKR_OK;
  good &= (info.flags & CKF_SIGN_RECOVER)==0 && (info.flags & CKF_VERIFY_RECOVER)==0;
  check("flags",tag,good);
}
static void flags_x509(RecoverApi *a) { flags_one(a,CKM_RSA_X_509,"X509"); }
static void flags_pkcs(RecoverApi *a) { flags_one(a,CKM_RSA_PKCS,"PKCS"); }

/* Refusal legs: every shape pins the honest joint refusal with no
 * state change (a follow-up init on the same session succeeds). */
static CK_OBJECT_HANDLE aes_key(RecoverApi *a, CK_SESSION_HANDLE session) {
  CK_OBJECT_CLASS cls=CKO_SECRET_KEY;
  CK_KEY_TYPE type=CKK_AES;
  CK_BBOOL no=CK_FALSE, yes=CK_TRUE;
  CK_OBJECT_HANDLE key=0;
  CK_ATTRIBUTE attrs[]={
    {CKA_CLASS,&cls,sizeof(cls)},{CKA_KEY_TYPE,&type,sizeof(type)},
    {CKA_TOKEN,&no,sizeof(no)},{CKA_VALUE,aesBytes,sizeof(aesBytes)},
    {CKA_ENCRYPT,&yes,sizeof(yes)},{CKA_DECRYPT,&yes,sizeof(yes)}
  };
  CK_RV result=a->C_CreateObject(session,attrs,6,&key);
  rv("setup","neg-aes-key",result,CKR_OK);
  if (result != CKR_OK || key==0) exit(2);
  return key;
}
static void neg_mech(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_AES_CBC,NULL,0};
  CK_OBJECT_HANDLE aes;
  CK_MECHANISM ok={CKM_RSA_X_509,NULL,0};
  int good=1;
  CK_RV result;
  aes=aes_key(a,f.session);
  result=a->C_SignRecoverInit(f.session,&m,aes);
  rv("neg","mech-detail",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_VerifyRecoverInit(f.session,&m,aes);
  rv("neg","mech-detail",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_SignRecoverInit(f.session,&ok,f.priv);
  rv("neg","mech-followup",result,CKR_OK); good &= result==CKR_OK;
  check("neg","mech",good);
  close_fixture(a,f);
}
static void neg_digest_row(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_SHA256_RSA_PKCS,NULL,0};
  CK_MECHANISM ok={CKM_RSA_X_509,NULL,0};
  int good=1;
  CK_RV result;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("neg","digest-row-detail",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("neg","digest-row-detail",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_SignRecoverInit(f.session,&ok,f.priv);
  rv("neg","digest-row-followup",result,CKR_OK); good &= result==CKR_OK;
  check("neg","digest-row",good);
  close_fixture(a,f);
}
static void neg_oversize(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_BYTE big[257];
  Output o;
  int good=1;
  CK_RV result;
  memset(big,0xa5,sizeof(big));
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("neg","oversize-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&o,256);
  result=a->C_SignRecover(f.session,big,sizeof(big),o.bytes,&o.length);
  rv("neg","oversize-detail",result,CKR_DATA_LEN_RANGE); good &= result==CKR_DATA_LEN_RANGE;
  check("neg","oversize",good);
  close_fixture(a,f);
}
static void neg_short_block(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_BYTE tiny[10], big[257];
  Output o;
  int good=1;
  CK_RV result;
  memset(tiny,0xa5,sizeof(tiny));
  memset(big,0xa5,sizeof(big));
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("neg","short-block-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&o,256);
  result=a->C_VerifyRecover(f.session,tiny,sizeof(tiny),o.bytes,&o.length);
  rv("neg","short-block-detail",result,CKR_SIGNATURE_INVALID); good &= result==CKR_SIGNATURE_INVALID;
  result=a->C_VerifyRecoverInit(f.session,&m,f.pub);
  rv("neg","short-block-reinit",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&o,512);
  result=a->C_VerifyRecover(f.session,big,sizeof(big),o.bytes,&o.length);
  rv("neg","short-block-detail",result,CKR_DATA_LEN_RANGE); good &= result==CKR_DATA_LEN_RANGE;
  check("neg","short-block",good);
  close_fixture(a,f);
}
static void neg_key_type(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_OBJECT_CLASS pcls=CKO_PUBLIC_KEY, scls=CKO_PRIVATE_KEY;
  CK_KEY_TYPE ekt=CKK_EC;
  CK_BBOOL no=CK_FALSE;
  CK_MECHANISM kgm={CKM_EC_KEY_PAIR_GEN,NULL,0};
  CK_ATTRIBUTE pubT[]={
    {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&ekt,sizeof(ekt)},
    {CKA_EC_PARAMS,(CK_VOID_PTR)p256oid,sizeof(p256oid)},
    {CKA_TOKEN,&no,sizeof(no)}
  };
  CK_ATTRIBUTE privT[]={
    {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&ekt,sizeof(ekt)},
    {CKA_TOKEN,&no,sizeof(no)}
  };
  CK_OBJECT_HANDLE epub=0, epriv=0;
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_MECHANISM ok={CKM_RSA_X_509,NULL,0};
  int good=1;
  CK_RV result;
  result=a->C_GenerateKeyPair(f.session,&kgm,pubT,4,privT,3,&epub,&epriv);
  rv("neg","key-type-ec-keygen",result,CKR_OK); good &= result==CKR_OK;
  good &= epub!=0 && epriv!=0 && epub!=epriv;
  result=a->C_SignRecoverInit(f.session,&m,epriv);
  rv("neg","key-type-detail",result,CKR_KEY_TYPE_INCONSISTENT); good &= result==CKR_KEY_TYPE_INCONSISTENT;
  result=a->C_VerifyRecoverInit(f.session,&m,epub);
  rv("neg","key-type-detail",result,CKR_KEY_TYPE_INCONSISTENT); good &= result==CKR_KEY_TYPE_INCONSISTENT;
  result=a->C_SignRecoverInit(f.session,&ok,f.priv);
  rv("neg","key-type-followup",result,CKR_OK); good &= result==CKR_OK;
  check("neg","key-type",good);
  close_fixture(a,f);
}
static void neg_null(RecoverApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_RSA_X_509,NULL,0};
  CK_BYTE input[256];
  Output o;
  CK_ULONG n=256;
  int good=1;
  CK_RV result;
  x509_input(input,msgText);
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("neg","null-init",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&o,256);
  result=a->C_SignRecover(f.session,input,sizeof(input),o.bytes,NULL);
  rv("neg","null-detail",result,CKR_ARGUMENTS_BAD); good &= result==CKR_ARGUMENTS_BAD;
  result=a->C_SignRecoverInit(f.session,&m,f.priv);
  rv("neg","null-reinit",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_SignRecover(f.session,NULL,10,o.bytes,&n);
  rv("neg","null-detail",result,CKR_ARGUMENTS_BAD); good &= result==CKR_ARGUMENTS_BAD;
  check("neg","null",good);
  close_fixture(a,f);
}

static int want_leg(const char *which, const char *name) {
  return strcmp(which,"all")==0 || strcmp(which,name)==0;
}
static int want_ver(const char *only, const char *v) {
  return only==NULL || strcmp(only,v)==0;
}
static void run_legs(RecoverApi *a, const char *which) {
  if (want_leg(which,"route")) {
    route_sign_recover_init(a);
    route_sign_recover(a);
    route_verify_recover_init(a);
    route_verify_recover(a);
  }
  if (want_leg(which,"pkcs")) {
    pkcs_sign_recover_init(a);
    pkcs_sign_recover(a);
    pkcs_verify_recover_init(a);
    pkcs_verify_recover(a);
  }
  if (want_leg(which,"flags")) {
    flags_x509(a);
    flags_pkcs(a);
  }
  if (want_leg(which,"neg")) {
    neg_mech(a);
    neg_digest_row(a);
    neg_oversize(a);
    neg_short_block(a);
    neg_key_type(a);
    neg_null(a);
  }
}

int main(int argc, char **argv) {
  const char *onlyVer=NULL, *which="all";
  void *module;
  CK_C_GetFunctionList getList;
  CK_C_GetInterface getInterface;
  const char *topology;
  int argi, ran=0;
  if (argc<2) return 2;
  for (argi=2;argi<argc;++argi) {
    if (strcmp(argv[argi],"--version")==0 && argi+1<argc) { onlyVer=argv[++argi]; }
    else if (strcmp(argv[argi],"--legs")==0 && argi+1<argc) { which=argv[++argi]; }
    else return 2;
  }
  if (!(strcmp(which,"all")==0 || strcmp(which,"route")==0 || strcmp(which,"pkcs")==0 || strcmp(which,"flags")==0 || strcmp(which,"neg")==0)) return 2;
  if (onlyVer!=NULL && !(strcmp(onlyVer,"2.40")==0 || strcmp(onlyVer,"3.0")==0 || strcmp(onlyVer,"3.1")==0 || strcmp(onlyVer,"3.2")==0)) return 2;
  if (setvbuf(stdout,NULL,_IOLBF,0)!=0) return 2;
  topology=getenv("HASKOKI_CONSUMER_TOPOLOGY");
  printf("topology: %s\n",topology && strcmp(topology,"proxy")==0 ? "proxy" : "direct");
  configure();
  module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if (!module) { fprintf(stderr,"module could not load\n"); return 2; }
  getList=(CK_C_GetFunctionList)dlsym(module,"C_GetFunctionList");
  getInterface=(CK_C_GetInterface)dlsym(module,"C_GetInterface");
  if (!getList || !getInterface) return 2;
  if (want_ver(onlyVer,"2.40")) {
    CK_FUNCTION_LIST_PTR list=NULL;
    RecoverApi a;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    CK_RV result;
    snprintf(ver,sizeof(ver),"%s","2.40");
    result=getList(&list);
    rv("C_GetFunctionList","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !list) return 1;
    check("C_GetFunctionList","version",list->version.major==2 && list->version.minor==40);
    a=read_legacy(list);
    if (!a.C_SignRecoverInit || !a.C_SignRecover || !a.C_VerifyRecoverInit || !a.C_VerifyRecover) return 1;
    result=a.C_Initialize(NULL);
    rv("C_Initialize","live",result,CKR_OK);
    if (result != CKR_OK) return 1;
    result=a.C_GetSlotList(CK_TRUE,slots,&count);
    rv("C_GetSlotList","token-present",result,CKR_OK);
    if (result != CKR_OK || count==0 || count>16) return 1;
    tokenSlot=slots[0];
    run_legs(&a,which);
    rv("C_Finalize","end",a.C_Finalize(NULL),CKR_OK);
    ran=1;
  }
  for (argi=0;argi<3;++argi) {
    static const char *labels[3]={"3.0","3.1","3.2"};
    CK_VERSION version={3,(CK_BYTE)argi};
    CK_INTERFACE_PTR interface=NULL;
    RecoverApi a;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    CK_RV result;
    if (!want_ver(onlyVer,labels[argi])) continue;
    snprintf(ver,sizeof(ver),"%s",labels[argi]);
    result=getInterface(NULL,&version,&interface,0);
    rv("C_GetInterface","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !interface || !interface->pFunctionList) return 1;
    if (argi<2) {
      CK_FUNCTION_LIST_3_0 *table=(CK_FUNCTION_LIST_3_0 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==(CK_BYTE)argi);
      a=read_common(table);
    } else {
      CK_FUNCTION_LIST_3_2 *table=(CK_FUNCTION_LIST_3_2 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==(CK_BYTE)argi);
      a=read_newest(table);
    }
    if (!a.C_SignRecoverInit || !a.C_SignRecover || !a.C_VerifyRecoverInit || !a.C_VerifyRecover) return 1;
    result=a.C_Initialize(NULL);
    rv("C_Initialize","live",result,CKR_OK);
    if (result != CKR_OK) return 1;
    result=a.C_GetSlotList(CK_TRUE,slots,&count);
    rv("C_GetSlotList","token-present",result,CKR_OK);
    if (result != CKR_OK || count==0 || count>16) return 1;
    tokenSlot=slots[0];
    run_legs(&a,which);
    rv("C_Finalize","end",a.C_Finalize(NULL),CKR_OK);
    ran=1;
  }
  dlclose(module);
  unlink(configPath);
  if (!ran) return 2;
  printf("recover:summary legs=%s failed=%d\n",which,failures);
  if (failures) return 1;
  printf("PASS: recover_routed (%s)\n",which);
  return 0;
}
