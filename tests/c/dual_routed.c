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

/* Dual-function wiring proof: the four combined-update entrypoints
 * route C -> FFI -> planner -> engine on every versioned table, and
 * each dual run equals its separate-sequences run at the C boundary
 * (same digest bytes, same cipher bytes). Final-coupling legs pin
 * the decrypt tail per PKCS#11 v3.0 section 5.17: the decrypt
 * final feeds nothing to the peer, so each leg passes the
 * recovered tail through an explicit peer update before the peer
 * final and then matches its separate sequences, tail included
 * (non-aligned padded input, fully-buffered AEAD input, verify
 * over non-aligned input). Partial-final legs pin the peer final
 * WITHOUT that explicit update: it covers only the update-fed
 * bytes. Lifecycle legs pin the
 * link against peer-slot transitions: a concluded-then-replaced
 * peer takes no tail, a link never crosses to another peer kind,
 * an update that emits nothing still closes the one-shot window,
 * and a concluded peer refuses the joint call before the cipher
 * side advances. Refusal legs pin the
 * joint contract: a missing peer refuses with no state change, and
 * malformed pointers terminate both sides.
 *
 * Usage: dual_routed <module> [--version 2.40|3.0|3.1|3.2]
 *                          [--legs route|equiv|neg|all]
 * Exit 0 iff every selected leg passes; 1 on any leg failure; 2 on
 * setup failure (usage, config, load, discovery).
 */
static int failures;
static char ver[8];
static CK_SLOT_ID tokenSlot;
static char configPath[256];
static CK_BYTE aesBytes[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static CK_BYTE macBytes[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
static CK_BYTE ivBytes[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static CK_BYTE nonce12[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
static const char ptText[] = "Block-one-here!!Block-two-here!!";
static const char ptShort[] = "Twenty-byte-plain!!.";

typedef struct {
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CreateObject C_CreateObject;
  CK_C_Digest C_Digest;
  CK_C_DigestInit C_DigestInit;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
} DualApi;
typedef struct { CK_SESSION_HANDLE session; CK_OBJECT_HANDLE aes, hmac; } Fixture;
typedef struct { CK_BYTE bytes[80]; CK_ULONG length; } Output;

static void check(const char *entry, const char *leg, int good) {
  printf("dual:%s/%s/%s check=%s\n",entry,leg,ver,good ? "ok" : "FAIL");
  if (!good) ++failures;
}
static void rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  printf("dual:%s/%s/%s rv=0x%lx expected=0x%lx\n",entry,leg,ver,(unsigned long)got,(unsigned long)want);
  if (got != want) ++failures;
}
static void rv_note(const char *entry, const char *leg, CK_RV got) {
  printf("dual:%s/%s/%s rv=0x%lx noted\n",entry,leg,ver,(unsigned long)got);
}
static void reset_output(Output *o, CK_ULONG n) { memset(o->bytes,0xa5,sizeof(o->bytes)); o->length=n; }
static void hex_of(const char *entry, const char *leg, const char *tag, const CK_BYTE *p, CK_ULONG n) {
  printf("dual:%s/%s/%s %s=",entry,leg,ver,tag);
  for (CK_ULONG i=0;i<n;++i) printf("%02x",p[i]);
  printf("\n");
}
static CK_OBJECT_HANDLE make_key(DualApi *a, CK_SESSION_HANDLE session, CK_KEY_TYPE type, CK_BYTE *value, CK_ULONG n, CK_BBOOL enc, CK_BBOOL dec, CK_BBOOL sign, CK_BBOOL verify) {
  CK_OBJECT_CLASS cls=CKO_SECRET_KEY;
  CK_BBOOL no=CK_FALSE;
  CK_OBJECT_HANDLE key=0;
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS,&cls,sizeof(cls)}, {CKA_KEY_TYPE,&type,sizeof(type)},
    {CKA_TOKEN,&no,sizeof(no)}, {CKA_PRIVATE,&no,sizeof(no)},
    {CKA_VALUE,value,n}, {CKA_ENCRYPT,&enc,sizeof(enc)},
    {CKA_DECRYPT,&dec,sizeof(dec)}, {CKA_SIGN,&sign,sizeof(sign)},
    {CKA_VERIFY,&verify,sizeof(verify)}
  };
  CK_RV result=a->C_CreateObject(session,attrs,sizeof(attrs)/sizeof(attrs[0]),&key);
  rv("fixture","create-key",result,CKR_OK);
  if (result != CKR_OK) exit(1);
  return key;
}
static Fixture fixture(DualApi *a) {
  Fixture f={0};
  CK_RV result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&f.session);
  rv("fixture","open",result,CKR_OK);
  if (result != CKR_OK) exit(1);
  f.aes=make_key(a,f.session,CKK_AES,aesBytes,32,CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);
  f.hmac=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_TRUE);
  return f;
}
static void close_fixture(DualApi *a, Fixture f) { rv("fixture","close",a->C_CloseSession(f.session),CKR_OK); }
static void configure(void) {
  char path[]="/tmp/haskoki-dual-config-XXXXXX";
  const char body[]="schema_version = 1\nprofile = \"real-crypto\"\n[storage]\nkind = \"memory\"\n[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\nprivate_library_context = true\n[trace]\nenabled = false\n";
  int fd=mkstemp(path);
  if (fd<0 || write(fd,body,sizeof(body)-1)!=(ssize_t)(sizeof(body)-1)) exit(2);
  close(fd);
  snprintf(configPath,sizeof(configPath),"%s",path);
  if (setenv("HASKOKI_CONFIG",configPath,1)!=0) exit(2);
}
static DualApi read_legacy(CK_FUNCTION_LIST *table) {
  DualApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_Digest=table->C_Digest;
  a.C_DigestInit=table->C_DigestInit;
  a.C_DigestUpdate=table->C_DigestUpdate;
  a.C_DigestFinal=table->C_DigestFinal;
  a.C_SignInit=table->C_SignInit;
  a.C_SignUpdate=table->C_SignUpdate;
  a.C_SignFinal=table->C_SignFinal;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_VerifyUpdate=table->C_VerifyUpdate;
  a.C_VerifyFinal=table->C_VerifyFinal;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_EncryptFinal=table->C_EncryptFinal;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_DecryptFinal=table->C_DecryptFinal;
  a.C_DigestEncryptUpdate=table->C_DigestEncryptUpdate;
  a.C_DecryptDigestUpdate=table->C_DecryptDigestUpdate;
  a.C_SignEncryptUpdate=table->C_SignEncryptUpdate;
  a.C_DecryptVerifyUpdate=table->C_DecryptVerifyUpdate;
  check("C_DigestEncryptUpdate","slot-present",a.C_DigestEncryptUpdate != NULL);
  check("C_DecryptDigestUpdate","slot-present",a.C_DecryptDigestUpdate != NULL);
  check("C_SignEncryptUpdate","slot-present",a.C_SignEncryptUpdate != NULL);
  check("C_DecryptVerifyUpdate","slot-present",a.C_DecryptVerifyUpdate != NULL);
  return a;
}
static DualApi read_common(CK_FUNCTION_LIST_3_0 *table) {
  DualApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_Digest=table->C_Digest;
  a.C_DigestInit=table->C_DigestInit;
  a.C_DigestUpdate=table->C_DigestUpdate;
  a.C_DigestFinal=table->C_DigestFinal;
  a.C_SignInit=table->C_SignInit;
  a.C_SignUpdate=table->C_SignUpdate;
  a.C_SignFinal=table->C_SignFinal;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_VerifyUpdate=table->C_VerifyUpdate;
  a.C_VerifyFinal=table->C_VerifyFinal;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_EncryptFinal=table->C_EncryptFinal;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_DecryptFinal=table->C_DecryptFinal;
  a.C_DigestEncryptUpdate=table->C_DigestEncryptUpdate;
  a.C_DecryptDigestUpdate=table->C_DecryptDigestUpdate;
  a.C_SignEncryptUpdate=table->C_SignEncryptUpdate;
  a.C_DecryptVerifyUpdate=table->C_DecryptVerifyUpdate;
  check("C_DigestEncryptUpdate","slot-present",a.C_DigestEncryptUpdate != NULL);
  check("C_DecryptDigestUpdate","slot-present",a.C_DecryptDigestUpdate != NULL);
  check("C_SignEncryptUpdate","slot-present",a.C_SignEncryptUpdate != NULL);
  check("C_DecryptVerifyUpdate","slot-present",a.C_DecryptVerifyUpdate != NULL);
  return a;
}
/* Route legs live after the newest reader; declared here so each
 * version block below stays short. */
static void route_digest_encrypt(DualApi *a);
static void route_decrypt_digest(DualApi *a);
static void route_sign_encrypt(DualApi *a);
static void route_decrypt_verify(DualApi *a);
static void equiv_digest_encrypt(DualApi *a);
static void equiv_decrypt_digest(DualApi *a);
static void equiv_sign_encrypt(DualApi *a);
static void equiv_decrypt_verify(DualApi *a);
static void equiv_final_nonaligned_digest(DualApi *a);
static void equiv_final_gcm_digest(DualApi *a);
static void equiv_final_nonaligned_verify(DualApi *a);
static void lifecycle_stale_link(DualApi *a);
static void lifecycle_peer_kind(DualApi *a);
static void lifecycle_zero_activity(DualApi *a);
static void lifecycle_staged_peer(DualApi *a);
static void neg_digest_encrypt(DualApi *a);
static void neg_decrypt_digest(DualApi *a);
static void neg_sign_encrypt(DualApi *a);
static void neg_decrypt_verify(DualApi *a);
static DualApi read_newest(CK_FUNCTION_LIST_3_2 *table) {
  DualApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_Digest=table->C_Digest;
  a.C_DigestInit=table->C_DigestInit;
  a.C_DigestUpdate=table->C_DigestUpdate;
  a.C_DigestFinal=table->C_DigestFinal;
  a.C_SignInit=table->C_SignInit;
  a.C_SignUpdate=table->C_SignUpdate;
  a.C_SignFinal=table->C_SignFinal;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_VerifyUpdate=table->C_VerifyUpdate;
  a.C_VerifyFinal=table->C_VerifyFinal;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_EncryptFinal=table->C_EncryptFinal;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_DecryptFinal=table->C_DecryptFinal;
  a.C_DigestEncryptUpdate=table->C_DigestEncryptUpdate;
  a.C_DecryptDigestUpdate=table->C_DecryptDigestUpdate;
  a.C_SignEncryptUpdate=table->C_SignEncryptUpdate;
  a.C_DecryptVerifyUpdate=table->C_DecryptVerifyUpdate;
  check("C_DigestEncryptUpdate","slot-present",a.C_DigestEncryptUpdate != NULL);
  check("C_DecryptDigestUpdate","slot-present",a.C_DecryptDigestUpdate != NULL);
  check("C_SignEncryptUpdate","slot-present",a.C_SignEncryptUpdate != NULL);
  check("C_DecryptVerifyUpdate","slot-present",a.C_DecryptVerifyUpdate != NULL);
  return a;
}
/* Route legs: each dual entrypoint executes through the table (one
 * 32-byte part; padded CBC streams 16, holds 16, final emits the
 * held block plus the pad block). */
static void route_digest_encrypt(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output u, e, d;
  int good=1;
  CK_RV result=a->C_DigestInit(f.session,&sha);
  rv("init","digest",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  rv("init","encrypt",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&u,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DigestEncryptUpdate","route",result,CKR_OK); good &= result==CKR_OK;
  good &= u.length==16;
  reset_output(&e,64);
  result=a->C_EncryptFinal(f.session,e.bytes,&e.length);
  rv("final","encrypt",result,CKR_OK); good &= result==CKR_OK;
  good &= e.length==32 && u.length+e.length==48;
  reset_output(&d,32);
  result=a->C_DigestFinal(f.session,d.bytes,&d.length);
  rv("final","digest",result,CKR_OK); good &= result==CKR_OK;
  good &= d.length==32;
  check("C_DigestEncryptUpdate","route",good);
  close_fixture(a,f);
}
static void route_decrypt_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output c1, c2, u, e, d;
  CK_BYTE ct[48];
  int good=1;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  rv("init","encrypt-ref",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&c1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,c1.bytes,&c1.length);
  rv("update","encrypt-ref-1",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&c2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,c2.bytes,&c2.length);
  rv("update","encrypt-ref-2",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&e,64);
  result=a->C_EncryptFinal(f.session,e.bytes,&e.length);
  rv("final","encrypt-ref",result,CKR_OK); good &= result==CKR_OK;
  good &= c1.length+c2.length+e.length==48;
  if (!good) { check("C_DecryptDigestUpdate","route",0); close_fixture(a,f); return; }
  memcpy(ct,c1.bytes,c1.length); memcpy(ct+c1.length,c2.bytes,c2.length); memcpy(ct+c1.length+c2.length,e.bytes,e.length);
  result=a->C_DigestInit(f.session,&sha);
  rv("init","digest",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  rv("init","decrypt",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&u,64);
  result=a->C_DecryptDigestUpdate(f.session,ct,48,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","route",result,CKR_OK); good &= result==CKR_OK;
  good &= u.length==32;
  reset_output(&e,64);
  result=a->C_DecryptFinal(f.session,e.bytes,&e.length);
  rv("final","decrypt",result,CKR_OK); good &= result==CKR_OK;
  good &= e.length==0 && u.length+e.length==32;
  reset_output(&d,32);
  result=a->C_DigestFinal(f.session,d.bytes,&d.length);
  rv("final","digest",result,CKR_OK); good &= result==CKR_OK;
  good &= d.length==32;
  check("C_DecryptDigestUpdate","route",good);
  close_fixture(a,f);
}
static void route_sign_encrypt(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output u, e, s;
  int good=1;
  CK_RV result=a->C_SignInit(f.session,&hmac,f.hmac);
  rv("init","sign",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  rv("init","encrypt",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&u,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_SignEncryptUpdate","route",result,CKR_OK); good &= result==CKR_OK;
  good &= u.length==16;
  reset_output(&e,64);
  result=a->C_EncryptFinal(f.session,e.bytes,&e.length);
  rv("final","encrypt",result,CKR_OK); good &= result==CKR_OK;
  good &= e.length==32 && u.length+e.length==48;
  reset_output(&s,32);
  result=a->C_SignFinal(f.session,s.bytes,&s.length);
  rv("final","sign",result,CKR_OK); good &= result==CKR_OK;
  good &= s.length==32;
  check("C_SignEncryptUpdate","route",good);
  close_fixture(a,f);
}
static void route_decrypt_verify(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output c1, c2, e, s, u, p;
  CK_BYTE ct[48], sig[32];
  int good=1;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  rv("init","encrypt-ref",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&c1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,c1.bytes,&c1.length);
  rv("update","encrypt-ref-1",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&c2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,c2.bytes,&c2.length);
  rv("update","encrypt-ref-2",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&e,64);
  result=a->C_EncryptFinal(f.session,e.bytes,&e.length);
  rv("final","encrypt-ref",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_SignInit(f.session,&hmac,f.hmac);
  rv("init","sign-ref",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,32);
  rv("update","sign-ref",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&s,32);
  result=a->C_SignFinal(f.session,s.bytes,&s.length);
  rv("final","sign-ref",result,CKR_OK); good &= result==CKR_OK;
  good &= c1.length+c2.length+e.length==48 && s.length==32;
  if (!good) { check("C_DecryptVerifyUpdate","route",0); close_fixture(a,f); return; }
  memcpy(ct,c1.bytes,c1.length); memcpy(ct+c1.length,c2.bytes,c2.length); memcpy(ct+c1.length+c2.length,e.bytes,e.length);
  memcpy(sig,s.bytes,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  rv("init","decrypt",result,CKR_OK); good &= result==CKR_OK;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac);
  rv("init","verify",result,CKR_OK); good &= result==CKR_OK;
  reset_output(&u,64);
  result=a->C_DecryptVerifyUpdate(f.session,ct,48,u.bytes,&u.length);
  rv("C_DecryptVerifyUpdate","route",result,CKR_OK); good &= result==CKR_OK;
  good &= u.length==32;
  reset_output(&p,64);
  result=a->C_DecryptFinal(f.session,p.bytes,&p.length);
  rv("final","decrypt",result,CKR_OK); good &= result==CKR_OK;
  good &= p.length==0 && u.length+p.length==32;
  result=a->C_VerifyFinal(f.session,sig,32);
  rv("final","verify",result,CKR_OK); good &= result==CKR_OK;
  check("C_DecryptVerifyUpdate","route",good);
  close_fixture(a,f);
}
/* Equivalence legs: each dual run (two parts, 20+12) must equal the
 * separate-sequences run over the same parts (same digest bytes,
 * same cipher bytes, same signature bytes). */
static void equiv_digest_encrypt(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output d1, d2, de, dd, r1, r2, re, rd;
  CK_BYTE ctDual[48], ctRef[48], dgDual[32], dgRef[32];
  int good=1, dgOk, ctOk;
  CK_RV result;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&d2,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,d2.bytes,&d2.length); good &= result==CKR_OK;
  reset_output(&de,64);
  result=a->C_EncryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length+d2.length+de.length==48 && dd.length==32;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,20); good &= result==CKR_OK;
  reset_output(&r1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,r1.bytes,&r1.length); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText+20,12); good &= result==CKR_OK;
  reset_output(&r2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,r2.bytes,&r2.length); good &= result==CKR_OK;
  reset_output(&re,64);
  result=a->C_EncryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(f.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= r1.length+r2.length+re.length==48 && rd.length==32;
  good &= d1.length==r1.length && d2.length==r2.length && de.length==re.length;
  if (!good) { check("C_DigestEncryptUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ctDual,d1.bytes,d1.length); memcpy(ctDual+d1.length,d2.bytes,d2.length); memcpy(ctDual+d1.length+d2.length,de.bytes,de.length);
  memcpy(ctRef,r1.bytes,r1.length); memcpy(ctRef+r1.length,r2.bytes,r2.length); memcpy(ctRef+r1.length+r2.length,re.bytes,re.length);
  memcpy(dgDual,dd.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgDual,dgRef,32)==0;
  ctOk = memcmp(ctDual,ctRef,48)==0;
  hex_of("C_DigestEncryptUpdate","equiv","dual-digest",dgDual,32);
  hex_of("C_DigestEncryptUpdate","equiv","ref-digest",dgRef,32);
  hex_of("C_DigestEncryptUpdate","equiv","dual-cipher",ctDual,48);
  hex_of("C_DigestEncryptUpdate","equiv","ref-cipher",ctRef,48);
  printf("dual:C_DigestEncryptUpdate/equiv/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ctOk ? "match" : "MISMATCH");
  check("C_DigestEncryptUpdate","equiv",dgOk && ctOk);
  close_fixture(a,f);
}
static void equiv_sign_encrypt(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output d1, d2, de, ds, r1, r2, re, rs;
  CK_BYTE ctDual[48], ctRef[48], sgDual[32], sgRef[32];
  int good=1, sgOk, ctOk;
  CK_RV result;
  result=a->C_SignInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&d2,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,d2.bytes,&d2.length); good &= result==CKR_OK;
  reset_output(&de,64);
  result=a->C_EncryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  reset_output(&ds,32);
  result=a->C_SignFinal(f.session,ds.bytes,&ds.length); good &= result==CKR_OK;
  good &= d1.length+d2.length+de.length==48 && ds.length==32;
  result=a->C_SignInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,20); good &= result==CKR_OK;
  reset_output(&r1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,r1.bytes,&r1.length); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText+20,12); good &= result==CKR_OK;
  reset_output(&r2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,r2.bytes,&r2.length); good &= result==CKR_OK;
  reset_output(&re,64);
  result=a->C_EncryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  reset_output(&rs,32);
  result=a->C_SignFinal(f.session,rs.bytes,&rs.length); good &= result==CKR_OK;
  good &= r1.length+r2.length+re.length==48 && rs.length==32;
  good &= d1.length==r1.length && d2.length==r2.length && de.length==re.length;
  if (!good) { check("C_SignEncryptUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ctDual,d1.bytes,d1.length); memcpy(ctDual+d1.length,d2.bytes,d2.length); memcpy(ctDual+d1.length+d2.length,de.bytes,de.length);
  memcpy(ctRef,r1.bytes,r1.length); memcpy(ctRef+r1.length,r2.bytes,r2.length); memcpy(ctRef+r1.length+r2.length,re.bytes,re.length);
  memcpy(sgDual,ds.bytes,32); memcpy(sgRef,rs.bytes,32);
  sgOk = memcmp(sgDual,sgRef,32)==0;
  ctOk = memcmp(ctDual,ctRef,48)==0;
  hex_of("C_SignEncryptUpdate","equiv","dual-sig",sgDual,32);
  hex_of("C_SignEncryptUpdate","equiv","ref-sig",sgRef,32);
  hex_of("C_SignEncryptUpdate","equiv","dual-cipher",ctDual,48);
  hex_of("C_SignEncryptUpdate","equiv","ref-cipher",ctRef,48);
  printf("dual:C_SignEncryptUpdate/equiv/%s sig=%s cipher=%s\n",ver,sgOk ? "match" : "MISMATCH",ctOk ? "match" : "MISMATCH");
  check("C_SignEncryptUpdate","equiv",sgOk && ctOk);
  close_fixture(a,f);
}
static void equiv_decrypt_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output c1, c2, ce, d1, d2, de, dd, r1, r2, re, rd;
  CK_BYTE ct[48], ptDual[32], ptRef[32], dgDual[32], dgRef[32];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&c1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,c1.bytes,&c1.length); good &= result==CKR_OK;
  reset_output(&c2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,c2.bytes,&c2.length); good &= result==CKR_OK;
  reset_output(&ce,64);
  result=a->C_EncryptFinal(f.session,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= c1.length+c2.length+ce.length==48;
  if (!good) { check("C_DecryptDigestUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ct,c1.bytes,c1.length); memcpy(ct+c1.length,c2.bytes,c2.length); memcpy(ct+c1.length+c2.length,ce.bytes,ce.length);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,64);
  result=a->C_DecryptDigestUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&d2,64);
  result=a->C_DecryptDigestUpdate(f.session,ct+32,16,d2.bytes,&d2.length); good &= result==CKR_OK;
  reset_output(&de,64);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length+d2.length+de.length==32 && dd.length==32;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&r1,64);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  reset_output(&r2,64);
  result=a->C_DecryptUpdate(f.session,ct+32,16,r2.bytes,&r2.length); good &= result==CKR_OK;
  reset_output(&re,64);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  good &= r1.length+r2.length+re.length==32;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,r2.bytes,r2.length); memcpy(ptRef+r1.length+r2.length,re.bytes,re.length);
  result=a->C_DigestUpdate(f.session,ptRef,32); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(f.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= rd.length==32;
  good &= d1.length==r1.length && d2.length==r2.length && de.length==re.length;
  if (!good) { check("C_DecryptDigestUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,d2.bytes,d2.length); memcpy(ptDual+d1.length+d2.length,de.bytes,de.length);
  memcpy(dgDual,dd.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgDual,dgRef,32)==0;
  ptOk = memcmp(ptDual,ptRef,32)==0;
  hex_of("C_DecryptDigestUpdate","equiv","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","equiv","ref-digest",dgRef,32);
  hex_of("C_DecryptDigestUpdate","equiv","dual-plain",ptDual,32);
  hex_of("C_DecryptDigestUpdate","equiv","ref-plain",ptRef,32);
  printf("dual:C_DecryptDigestUpdate/equiv/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","equiv",dgOk && ptOk);
  close_fixture(a,f);
}
static void equiv_decrypt_verify(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output c1, c2, ce, sg, d1, d2, de, r1, r2, re;
  CK_BYTE ct[48], sig[32], ptDual[32], ptRef[32];
  int good=1, vfOk, ptOk;
  CK_RV result, vfDual, vfRef;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&c1,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,20,c1.bytes,&c1.length); good &= result==CKR_OK;
  reset_output(&c2,64);
  result=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText+20,12,c2.bytes,&c2.length); good &= result==CKR_OK;
  reset_output(&ce,64);
  result=a->C_EncryptFinal(f.session,ce.bytes,&ce.length); good &= result==CKR_OK;
  result=a->C_SignInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,32); good &= result==CKR_OK;
  reset_output(&sg,32);
  result=a->C_SignFinal(f.session,sg.bytes,&sg.length); good &= result==CKR_OK;
  good &= c1.length+c2.length+ce.length==48 && sg.length==32;
  if (!good) { check("C_DecryptVerifyUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ct,c1.bytes,c1.length); memcpy(ct+c1.length,c2.bytes,c2.length); memcpy(ct+c1.length+c2.length,ce.bytes,ce.length);
  memcpy(sig,sg.bytes,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  reset_output(&d1,64);
  result=a->C_DecryptVerifyUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&d2,64);
  result=a->C_DecryptVerifyUpdate(f.session,ct+32,16,d2.bytes,&d2.length); good &= result==CKR_OK;
  reset_output(&de,64);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  good &= d1.length+d2.length+de.length==32;
  vfDual=a->C_VerifyFinal(f.session,sig,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&r1,64);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  reset_output(&r2,64);
  result=a->C_DecryptUpdate(f.session,ct+32,16,r2.bytes,&r2.length); good &= result==CKR_OK;
  reset_output(&re,64);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  good &= r1.length+r2.length+re.length==32;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,r2.bytes,r2.length); memcpy(ptRef+r1.length+r2.length,re.bytes,re.length);
  result=a->C_VerifyUpdate(f.session,ptRef,32); good &= result==CKR_OK;
  vfRef=a->C_VerifyFinal(f.session,sig,32);
  good &= d1.length==r1.length && d2.length==r2.length && de.length==re.length;
  if (!good) { check("C_DecryptVerifyUpdate","equiv",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,d2.bytes,d2.length); memcpy(ptDual+d1.length+d2.length,de.bytes,de.length);
  vfOk = vfDual==CKR_OK && vfRef==CKR_OK;
  ptOk = memcmp(ptDual,ptRef,32)==0;
  hex_of("C_DecryptVerifyUpdate","equiv","dual-plain",ptDual,32);
  hex_of("C_DecryptVerifyUpdate","equiv","ref-plain",ptRef,32);
  printf("dual:C_DecryptVerifyUpdate/equiv/%s verify=%s cipher=%s\n",ver,vfOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptVerifyUpdate","equiv",vfOk && ptOk);
  close_fixture(a,f);
}
/* Final-coupling legs: decrypt-direction duals must equal their
 * separate sequences even when the decrypt final emits recovered
 * plaintext (non-aligned padded input, fully-buffered AEAD input,
 * verify over non-aligned input). Per section 5.17.2/5.17.4 the
 * decrypt final feeds NOTHING to the peer: the caller passes the
 * recovered tail through an explicit peer update before the peer
 * final (section 5.17.2's own example C_DigestUpdates the 2 tail
 * bytes after C_DecryptFinal). Each leg pins its tail width (a
 * leg with an empty tail would prove nothing), performs that
 * explicit tail update, and then pins the byte equality (same
 * digest bytes, same plaintext bytes, same verdicts). */
static void equiv_final_nonaligned_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, d1, de, dd, r1, re, rd;
  CK_BYTE ct[32], ptDual[20], ptRef[20], dgDual[32], dgRef[32];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==32;
  if (!good) { check("C_DecryptDigestUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptDigestUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,32);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  /* Section 5.17.2 shape: the tail reaches the digest ONLY through
   * this explicit update (the decrypt final feeds nothing). */
  result=a->C_DigestUpdate(f.session,de.bytes,de.length); good &= result==CKR_OK;
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length==16 && de.length==4 && dd.length==32;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&r1,32);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  reset_output(&re,32);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  good &= r1.length==16 && re.length==4;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,re.bytes,re.length);
  good &= memcmp(ptRef,ptShort,20)==0;
  result=a->C_DigestUpdate(f.session,ptRef,20); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(f.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= rd.length==32;
  good &= d1.length==r1.length && de.length==re.length;
  if (!good) { check("C_DecryptDigestUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,de.bytes,de.length);
  memcpy(dgDual,dd.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgDual,dgRef,32)==0;
  ptOk = memcmp(ptDual,ptRef,20)==0;
  hex_of("C_DecryptDigestUpdate","equiv-final","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","equiv-final","ref-digest",dgRef,32);
  hex_of("C_DecryptDigestUpdate","equiv-final","dual-plain",ptDual,20);
  hex_of("C_DecryptDigestUpdate","equiv-final","ref-plain",ptRef,20);
  printf("dual:C_DecryptDigestUpdate/equiv-final/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","equiv-final",dgOk && ptOk);
  close_fixture(a,f);
}
static void equiv_final_gcm_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_GCM_PARAMS gp={nonce12,12,96,NULL,0,128};
  CK_MECHANISM gcm={CKM_AES_GCM,(CK_VOID_PTR)&gp,sizeof(gp)};
  Output ce, d1, de, dd, r1, re, rd;
  CK_BYTE ct[48], ptDual[32], ptRef[32], dgDual[32], dgRef[32];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&ce,48);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptText,32,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==48;
  if (!good) { check("C_DecryptDigestUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,48);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&d1,48);
  result=a->C_DecryptDigestUpdate(f.session,ct,48,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,48);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  /* Section 5.17.2 shape: the tail reaches the digest ONLY through
   * this explicit update (the decrypt final feeds nothing). */
  result=a->C_DigestUpdate(f.session,de.bytes,de.length); good &= result==CKR_OK;
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length==0 && de.length==32 && dd.length==32;
  result=a->C_DecryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&r1,48);
  result=a->C_DecryptUpdate(f.session,ct,48,r1.bytes,&r1.length); good &= result==CKR_OK;
  reset_output(&re,48);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  good &= r1.length==0 && re.length==32;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,re.bytes,re.length);
  good &= memcmp(ptRef,ptText,32)==0;
  result=a->C_DigestUpdate(f.session,ptRef,32); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(f.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= rd.length==32;
  if (!good) { check("C_DecryptDigestUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,de.bytes,de.length);
  memcpy(dgDual,dd.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgDual,dgRef,32)==0;
  ptOk = memcmp(ptDual,ptRef,32)==0;
  hex_of("C_DecryptDigestUpdate","equiv-final","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","equiv-final","ref-digest",dgRef,32);
  hex_of("C_DecryptDigestUpdate","equiv-final","dual-plain",ptDual,32);
  hex_of("C_DecryptDigestUpdate","equiv-final","ref-plain",ptRef,32);
  printf("dual:C_DecryptDigestUpdate/equiv-final/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","equiv-final",dgOk && ptOk);
  close_fixture(a,f);
}
static void equiv_final_nonaligned_verify(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, sg, d1, de, r1, re;
  CK_BYTE ct[32], sig[32], ptDual[20], ptRef[20];
  int good=1, vfOk, ptOk;
  CK_RV result, vfDual, vfRef;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  result=a->C_SignInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1); good &= result==CKR_OK;
  reset_output(&sg,32);
  result=a->C_SignFinal(f.session,sg.bytes,&sg.length); good &= result==CKR_OK;
  good &= ce.length==32 && sg.length==32;
  if (!good) { check("C_DecryptVerifyUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  memcpy(sig,sg.bytes,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptVerifyUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,32);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  good &= d1.length==16 && de.length==4;
  /* Section 5.17.4 shape: the tail reaches the verify peer ONLY
   * through this explicit update (the decrypt final feeds nothing). */
  result=a->C_VerifyUpdate(f.session,de.bytes,de.length); good &= result==CKR_OK;
  vfDual=a->C_VerifyFinal(f.session,sig,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&r1,32);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  reset_output(&re,32);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  good &= r1.length==16 && re.length==4;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,re.bytes,re.length);
  good &= memcmp(ptRef,ptShort,20)==0;
  result=a->C_VerifyUpdate(f.session,ptRef,20); good &= result==CKR_OK;
  vfRef=a->C_VerifyFinal(f.session,sig,32);
  good &= d1.length==r1.length && de.length==re.length;
  if (!good) { check("C_DecryptVerifyUpdate","equiv-final",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,de.bytes,de.length);
  vfOk = vfDual==CKR_OK && vfRef==CKR_OK;
  ptOk = memcmp(ptDual,ptRef,20)==0;
  hex_of("C_DecryptVerifyUpdate","equiv-final","dual-plain",ptDual,20);
  hex_of("C_DecryptVerifyUpdate","equiv-final","ref-plain",ptRef,20);
  printf("dual:C_DecryptVerifyUpdate/equiv-final/%s verify=%s cipher=%s\n",ver,vfOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptVerifyUpdate","equiv-final",vfOk && ptOk);
  close_fixture(a,f);
}
/* Partial-final legs: the spec-example partial state. A peer
 * final WITHOUT the explicit tail update covers ONLY the
 * update-fed bytes (section 5.17.2: the 2 tail bytes "are not
 * passed on to be digested" by the decrypt final). Each leg pins
 * its widths, the equality against the update-fed-only
 * reference, AND the inequality against the full-message
 * reference (a leg that cannot tell partial from full proves
 * nothing). */
static void partial_final_nonaligned_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, d1, de, dd, rp, rf;
  CK_BYTE ct[32], dgDual[32], dgPart[32], dgFull[32];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==32;
  if (!good) { check("C_DecryptDigestUpdate","partial-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptDigestUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,32);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  /* NO explicit tail update: the peer final must cover exactly the
   * 16 update-fed bytes. */
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length==16 && de.length==4 && dd.length==32;
  good &= memcmp(d1.bytes,ptShort,16)==0;
  good &= memcmp(de.bytes,ptShort+16,4)==0;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptShort,16); good &= result==CKR_OK;
  reset_output(&rp,32);
  result=a->C_DigestFinal(f.session,rp.bytes,&rp.length); good &= result==CKR_OK;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptShort,20); good &= result==CKR_OK;
  reset_output(&rf,32);
  result=a->C_DigestFinal(f.session,rf.bytes,&rf.length); good &= result==CKR_OK;
  good &= rp.length==32 && rf.length==32;
  if (!good) { check("C_DecryptDigestUpdate","partial-final",0); close_fixture(a,f); return; }
  memcpy(dgDual,dd.bytes,32); memcpy(dgPart,rp.bytes,32); memcpy(dgFull,rf.bytes,32);
  dgOk = memcmp(dgDual,dgPart,32)==0 && memcmp(dgDual,dgFull,32)!=0;
  ptOk = memcmp(dgPart,dgFull,32)!=0;
  hex_of("C_DecryptDigestUpdate","partial-final","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","partial-final","part-digest",dgPart,32);
  hex_of("C_DecryptDigestUpdate","partial-final","full-digest",dgFull,32);
  printf("dual:C_DecryptDigestUpdate/partial-final/%s digest=%s control=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","partial-final",dgOk && ptOk);
  close_fixture(a,f);
}
static void partial_final_gcm_digest(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_GCM_PARAMS gp={nonce12,12,96,NULL,0,128};
  CK_MECHANISM gcm={CKM_AES_GCM,(CK_VOID_PTR)&gp,sizeof(gp)};
  Output ce, d1, de, dd, rp, rf;
  CK_BYTE ct[48], dgDual[32], dgPart[32], dgFull[32];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&ce,48);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptText,32,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==48;
  if (!good) { check("C_DecryptDigestUpdate","partial-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,48);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&d1,48);
  result=a->C_DecryptDigestUpdate(f.session,ct,48,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,48);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  /* NO explicit tail update: the update fed zero bytes, so the
   * peer final must cover exactly the empty input. */
  reset_output(&dd,32);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length); good &= result==CKR_OK;
  good &= d1.length==0 && de.length==32 && dd.length==32;
  good &= memcmp(de.bytes,ptText,32)==0;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  reset_output(&rp,32);
  result=a->C_DigestFinal(f.session,rp.bytes,&rp.length); good &= result==CKR_OK;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,32); good &= result==CKR_OK;
  reset_output(&rf,32);
  result=a->C_DigestFinal(f.session,rf.bytes,&rf.length); good &= result==CKR_OK;
  good &= rp.length==32 && rf.length==32;
  if (!good) { check("C_DecryptDigestUpdate","partial-final",0); close_fixture(a,f); return; }
  memcpy(dgDual,dd.bytes,32); memcpy(dgPart,rp.bytes,32); memcpy(dgFull,rf.bytes,32);
  dgOk = memcmp(dgDual,dgPart,32)==0 && memcmp(dgDual,dgFull,32)!=0;
  ptOk = memcmp(dgPart,dgFull,32)!=0;
  hex_of("C_DecryptDigestUpdate","partial-final","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","partial-final","empty-digest",dgPart,32);
  hex_of("C_DecryptDigestUpdate","partial-final","full-digest",dgFull,32);
  printf("dual:C_DecryptDigestUpdate/partial-final/%s digest=%s control=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","partial-final",dgOk && ptOk);
  close_fixture(a,f);
}
static void partial_final_nonaligned_verify(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, sg, d1, de;
  CK_BYTE ct[32], sig[32];
  int good=1;
  CK_RV result, vfDual, vfFull;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  result=a->C_SignInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1); good &= result==CKR_OK;
  reset_output(&sg,32);
  result=a->C_SignFinal(f.session,sg.bytes,&sg.length); good &= result==CKR_OK;
  good &= ce.length==32 && sg.length==32;
  if (!good) { check("C_DecryptVerifyUpdate","partial-final",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  memcpy(sig,sg.bytes,32);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptVerifyUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&de,32);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  good &= d1.length==16 && de.length==4;
  /* NO explicit tail update: the peer holds only the 16
   * update-fed bytes, so the 20-byte tag must NOT verify. */
  vfDual=a->C_VerifyFinal(f.session,sig,32);
  rv("C_DecryptVerifyUpdate","partial-final",vfDual,CKR_SIGNATURE_INVALID);
  good &= vfDual==CKR_SIGNATURE_INVALID;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  result=a->C_VerifyUpdate(f.session,(CK_BYTE_PTR)ptShort,20); good &= result==CKR_OK;
  vfFull=a->C_VerifyFinal(f.session,sig,32);
  rv("setup","partial-final-control",vfFull,CKR_OK); good &= vfFull==CKR_OK;
  check("C_DecryptVerifyUpdate","partial-final",good);
  close_fixture(a,f);
}
/* Lifecycle legs: the decrypt-final peer link follows the peer
 * slot lifecycle. Each leg pins its widths, then the byte or
 * verdict equality against the separate-sequences reference. */
static void lifecycle_stale_link(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, d1, dd1, de, dd2, r1, rd1, re, rd2;
  CK_BYTE ct[32], dgDual1[32], dgDual2[32], dgRef1[32], dgRef2[32], ptDual[20], ptRef[20];
  int good=1, dgOk, ptOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==32;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-stale-link",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptDigestUpdate(f.session,ct,32,d1.bytes,&d1.length); good &= result==CKR_OK;
  reset_output(&dd1,32);
  result=a->C_DigestFinal(f.session,dd1.bytes,&dd1.length); good &= result==CKR_OK;
  good &= d1.length==16 && dd1.length==32;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  reset_output(&de,32);
  result=a->C_DecryptFinal(f.session,de.bytes,&de.length); good &= result==CKR_OK;
  reset_output(&dd2,32);
  result=a->C_DigestFinal(f.session,dd2.bytes,&dd2.length); good &= result==CKR_OK;
  good &= de.length==4 && dd2.length==32;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&r1,32);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,r1.bytes,r1.length); good &= result==CKR_OK;
  reset_output(&rd1,32);
  result=a->C_DigestFinal(f.session,rd1.bytes,&rd1.length); good &= result==CKR_OK;
  good &= r1.length==16 && rd1.length==32;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  reset_output(&re,32);
  result=a->C_DecryptFinal(f.session,re.bytes,&re.length); good &= result==CKR_OK;
  reset_output(&rd2,32);
  result=a->C_DigestFinal(f.session,rd2.bytes,&rd2.length); good &= result==CKR_OK;
  good &= re.length==4 && rd2.length==32;
  good &= d1.length==r1.length && de.length==re.length;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-stale-link",0); close_fixture(a,f); return; }
  memcpy(ptDual,d1.bytes,d1.length); memcpy(ptDual+d1.length,de.bytes,de.length);
  memcpy(ptRef,r1.bytes,r1.length); memcpy(ptRef+r1.length,re.bytes,re.length);
  memcpy(dgDual1,dd1.bytes,32); memcpy(dgRef1,rd1.bytes,32);
  memcpy(dgDual2,dd2.bytes,32); memcpy(dgRef2,rd2.bytes,32);
  dgOk = memcmp(dgDual1,dgRef1,32)==0 && memcmp(dgDual2,dgRef2,32)==0;
  ptOk = memcmp(ptDual,ptRef,20)==0;
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","dual-digest-1",dgDual1,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","ref-digest-1",dgRef1,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","dual-digest-2",dgDual2,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","ref-digest-2",dgRef2,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","dual-plain",ptDual,20);
  hex_of("C_DecryptDigestUpdate","lifecycle-stale-link","ref-plain",ptRef,20);
  printf("dual:C_DecryptDigestUpdate/lifecycle-stale-link/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ptOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","lifecycle-stale-link",dgOk && ptOk);
  close_fixture(a,f);
}
static void lifecycle_peer_kind(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, v1, d1, dd, rd;
  CK_BYTE ct[48], dgDual[32], dgRef[32], stream[64];
  int good=1, dgOk, ctOk;
  CK_RV result, dfRv;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,48);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptText,32,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==48;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-peer-kind",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,48);
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  result=a->C_VerifyInit(f.session,&hmac,f.hmac); good &= result==CKR_OK;
  reset_output(&v1,32);
  result=a->C_DecryptVerifyUpdate(f.session,ct,32,v1.bytes,&v1.length); good &= result==CKR_OK;
  good &= v1.length==16;
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1); good &= result==CKR_OK;
  reset_output(&d1,32);
  result=a->C_DecryptDigestUpdate(f.session,ct+32,16,d1.bytes,&d1.length); good &= result==CKR_OK;
  good &= d1.length==16;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-peer-kind",0); close_fixture(a,f); return; }
  reset_output(&dd,32);
  dfRv=a->C_DigestFinal(f.session,dd.bytes,&dd.length);
  rv("C_DecryptDigestUpdate","lifecycle-peer-kind",dfRv,CKR_OK);
  good &= dfRv==CKR_OK && dd.length==32;
  memcpy(stream,ptShort,20); memcpy(stream+20,d1.bytes,d1.length);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,stream,20+d1.length); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(f.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= rd.length==32;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-peer-kind",0); close_fixture(a,f); return; }
  memcpy(dgDual,dd.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgDual,dgRef,32)==0;
  ctOk = v1.length==16 && d1.length==16;
  hex_of("C_DecryptDigestUpdate","lifecycle-peer-kind","dual-digest",dgDual,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-peer-kind","ref-digest",dgRef,32);
  printf("dual:C_DecryptDigestUpdate/lifecycle-peer-kind/%s digest=%s cipher=%s\n",ver,dgOk ? "match" : "MISMATCH",ctOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","lifecycle-peer-kind",dgOk && ctOk);
  close_fixture(a,f);
}
static void lifecycle_zero_activity(DualApi *a) {
  Fixture f=fixture(a);
  Fixture g=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_GCM_PARAMS gp={nonce12,12,96,NULL,0,128};
  CK_MECHANISM gcm={CKM_AES_GCM,(CK_VOID_PTR)&gp,sizeof(gp)};
  Output ce, d1, os, fo, rd;
  CK_BYTE ct[48], dgOne[32], dgRef[32];
  int good=1, winClosed=0, dgOk, ctOk;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&ce,48);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptText,32,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==48;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-zero-activity",0); close_fixture(a,g); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,48);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DecryptInit(f.session,&gcm,f.aes); good &= result==CKR_OK;
  reset_output(&d1,48);
  result=a->C_DecryptDigestUpdate(f.session,ct,48,d1.bytes,&d1.length); good &= result==CKR_OK;
  good &= d1.length==0;
  reset_output(&os,32);
  result=a->C_Digest(f.session,(CK_BYTE_PTR)ptText,32,os.bytes,&os.length);
  rv("C_DecryptDigestUpdate","lifecycle-zero-activity",result,CKR_OPERATION_ACTIVE);
  winClosed = result==CKR_OPERATION_ACTIVE;
  good &= winClosed;
  result=a->C_DigestInit(g.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(g.session,(CK_BYTE_PTR)ptText,0); good &= result==CKR_OK;
  reset_output(&os,32);
  result=a->C_Digest(g.session,(CK_BYTE_PTR)ptText,32,os.bytes,&os.length);
  rv("C_DecryptDigestUpdate","lifecycle-zero-activity",result,CKR_OPERATION_ACTIVE);
  good &= result==CKR_OPERATION_ACTIVE;
  result=a->C_DigestInit(g.session,&sha); good &= result==CKR_OK;
  reset_output(&fo,32);
  result=a->C_Digest(g.session,(CK_BYTE_PTR)ptText,32,fo.bytes,&fo.length); good &= result==CKR_OK;
  good &= fo.length==32;
  result=a->C_DigestInit(g.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(g.session,(CK_BYTE_PTR)ptText,32); good &= result==CKR_OK;
  reset_output(&rd,32);
  result=a->C_DigestFinal(g.session,rd.bytes,&rd.length); good &= result==CKR_OK;
  good &= rd.length==32;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-zero-activity",0); close_fixture(a,g); close_fixture(a,f); return; }
  memcpy(dgOne,fo.bytes,32); memcpy(dgRef,rd.bytes,32);
  dgOk = memcmp(dgOne,dgRef,32)==0;
  ctOk = d1.length==0;
  hex_of("C_DecryptDigestUpdate","lifecycle-zero-activity","one-shot-digest",dgOne,32);
  hex_of("C_DecryptDigestUpdate","lifecycle-zero-activity","ref-digest",dgRef,32);
  printf("dual:C_DecryptDigestUpdate/lifecycle-zero-activity/%s verdict=%s cipher=%s\n",ver,(winClosed && dgOk) ? "match" : "MISMATCH",ctOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","lifecycle-zero-activity",winClosed && dgOk && ctOk);
  close_fixture(a,g);
  close_fixture(a,f);
}
static void lifecycle_staged_peer(DualApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  Output ce, dd, u, r1;
  CK_BYTE ct[32];
  CK_ULONG qlen=0;
  int good=1, vfOk, ctOk;
  CK_RV result, qRv, uRv;
  result=a->C_EncryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  reset_output(&ce,32);
  result=a->C_Encrypt(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1,ce.bytes,&ce.length); good &= result==CKR_OK;
  good &= ce.length==32;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-staged-peer",0); close_fixture(a,f); return; }
  memcpy(ct,ce.bytes,32);
  result=a->C_DigestInit(f.session,&sha); good &= result==CKR_OK;
  result=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptShort,sizeof(ptShort)-1); good &= result==CKR_OK;
  reset_output(&dd,16);
  result=a->C_DigestFinal(f.session,dd.bytes,&dd.length);
  rv("C_DecryptDigestUpdate","lifecycle-staged-peer",result,CKR_BUFFER_TOO_SMALL);
  good &= result==CKR_BUFFER_TOO_SMALL;
  result=a->C_DecryptInit(f.session,&pad,f.aes); good &= result==CKR_OK;
  qlen=64;
  qRv=a->C_DecryptDigestUpdate(f.session,ct,32,NULL,&qlen);
  rv("C_DecryptDigestUpdate","lifecycle-staged-peer",qRv,CKR_OPERATION_NOT_INITIALIZED);
  good &= qRv==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&u,64);
  uRv=a->C_DecryptDigestUpdate(f.session,ct,32,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","lifecycle-staged-peer",uRv,CKR_OPERATION_NOT_INITIALIZED);
  good &= uRv==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&r1,32);
  result=a->C_DecryptUpdate(f.session,ct,32,r1.bytes,&r1.length); good &= result==CKR_OK;
  good &= r1.length==16;
  if (!good) { check("C_DecryptDigestUpdate","lifecycle-staged-peer",0); close_fixture(a,f); return; }
  ctOk = memcmp(r1.bytes,ptShort,16)==0;
  vfOk = qRv==CKR_OPERATION_NOT_INITIALIZED && uRv==CKR_OPERATION_NOT_INITIALIZED;
  hex_of("C_DecryptDigestUpdate","lifecycle-staged-peer","first-block",r1.bytes,16);
  printf("dual:C_DecryptDigestUpdate/lifecycle-staged-peer/%s verdict=%s cipher=%s\n",ver,vfOk ? "match" : "MISMATCH",ctOk ? "match" : "MISMATCH");
  check("C_DecryptDigestUpdate","lifecycle-staged-peer",vfOk && ctOk);
  close_fixture(a,f);
}
/* Refusal legs (3.2 only): a missing peer refuses with no state
 * change (the live side still serves separate calls); malformed
 * pointers refuse and terminate both sides. Null-len follow-up
 * probes log their measured return values (issue #30 evidence)
 * and fold into the leg verdict; other follow-ups run silently. */
static void neg_digest_encrypt(DualApi *a) {
  Fixture f;
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  Output u, q;
  int good;
  CK_RV result, follow;
  f=fixture(a);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DigestEncryptUpdate","neg-missing-peer",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  check("C_DigestEncryptUpdate","neg-missing-peer",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  reset_output(&u,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DigestEncryptUpdate","neg-missing-cipher",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DigestEncryptUpdate","neg-missing-cipher",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_SignInit(f.session,&hmac,f.hmac);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DigestEncryptUpdate","neg-wrong-pair",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  follow=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DigestEncryptUpdate","neg-wrong-pair",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  result=a->C_DigestEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,NULL);
  rv("C_DigestEncryptUpdate","neg-null-len",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  rv_note("C_DigestEncryptUpdate","neg-null-len-followup-cipher",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  rv_note("C_DigestEncryptUpdate","neg-null-len-followup-peer",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DigestEncryptUpdate","neg-null-len",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DigestEncryptUpdate(f.session,NULL,32,u.bytes,&u.length);
  rv("C_DigestEncryptUpdate","neg-null-part",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DigestEncryptUpdate","neg-null-part",good);
  close_fixture(a,f);
}
static void neg_decrypt_digest(DualApi *a) {
  Fixture f;
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  Output u, q;
  int good;
  CK_RV result, follow;
  f=fixture(a);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptDigestUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","neg-missing-peer",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  check("C_DecryptDigestUpdate","neg-missing-peer",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  reset_output(&u,64);
  result=a->C_DecryptDigestUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","neg-missing-cipher",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DecryptDigestUpdate","neg-missing-cipher",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_VerifyInit(f.session,&hmac,f.hmac);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptDigestUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","neg-wrong-pair",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  follow=a->C_VerifyUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DecryptDigestUpdate","neg-wrong-pair",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  result=a->C_DecryptDigestUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,NULL);
  rv("C_DecryptDigestUpdate","neg-null-len",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  rv_note("C_DecryptDigestUpdate","neg-null-len-followup-cipher",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  rv_note("C_DecryptDigestUpdate","neg-null-len-followup-peer",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DecryptDigestUpdate","neg-null-len",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptDigestUpdate(f.session,NULL,32,u.bytes,&u.length);
  rv("C_DecryptDigestUpdate","neg-null-part",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DecryptDigestUpdate","neg-null-part",good);
  close_fixture(a,f);
}
static void neg_sign_encrypt(DualApi *a) {
  Fixture f;
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  Output u, q;
  int good;
  CK_RV result, follow;
  f=fixture(a);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_SignEncryptUpdate","neg-missing-peer",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  check("C_SignEncryptUpdate","neg-missing-peer",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_SignInit(f.session,&hmac,f.hmac);
  reset_output(&u,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_SignEncryptUpdate","neg-missing-cipher",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_SignEncryptUpdate","neg-missing-cipher",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_SignEncryptUpdate","neg-wrong-pair",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_SignEncryptUpdate","neg-wrong-pair",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_SignInit(f.session,&hmac,f.hmac);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  result=a->C_SignEncryptUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,NULL);
  rv("C_SignEncryptUpdate","neg-null-len",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  rv_note("C_SignEncryptUpdate","neg-null-len-followup-cipher",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  rv_note("C_SignEncryptUpdate","neg-null-len-followup-peer",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_SignEncryptUpdate","neg-null-len",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_SignInit(f.session,&hmac,f.hmac);
  result=a->C_EncryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_SignEncryptUpdate(f.session,NULL,32,u.bytes,&u.length);
  rv("C_SignEncryptUpdate","neg-null-part",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_EncryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_SignUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_SignEncryptUpdate","neg-null-part",good);
  close_fixture(a,f);
}
static void neg_decrypt_verify(DualApi *a) {
  Fixture f;
  CK_MECHANISM sha={CKM_SHA256,NULL,0};
  CK_MECHANISM pad={CKM_AES_CBC_PAD,ivBytes,sizeof(ivBytes)};
  CK_MECHANISM hmac={CKM_SHA256_HMAC,NULL,0};
  Output u, q;
  int good;
  CK_RV result, follow;
  f=fixture(a);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptVerifyUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptVerifyUpdate","neg-missing-peer",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  check("C_DecryptVerifyUpdate","neg-missing-peer",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_VerifyInit(f.session,&hmac,f.hmac);
  reset_output(&u,64);
  result=a->C_DecryptVerifyUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptVerifyUpdate","neg-missing-cipher",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_VerifyUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DecryptVerifyUpdate","neg-missing-cipher",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_DigestInit(f.session,&sha);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptVerifyUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,&u.length);
  rv("C_DecryptVerifyUpdate","neg-wrong-pair",result,CKR_OPERATION_NOT_INITIALIZED);
  good = result==CKR_OPERATION_NOT_INITIALIZED;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OK;
  follow=a->C_DigestUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OK;
  check("C_DecryptVerifyUpdate","neg-wrong-pair",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_VerifyInit(f.session,&hmac,f.hmac);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  result=a->C_DecryptVerifyUpdate(f.session,(CK_BYTE_PTR)ptText,32,u.bytes,NULL);
  rv("C_DecryptVerifyUpdate","neg-null-len",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  rv_note("C_DecryptVerifyUpdate","neg-null-len-followup-cipher",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_VerifyUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  rv_note("C_DecryptVerifyUpdate","neg-null-len-followup-peer",follow);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DecryptVerifyUpdate","neg-null-len",good);
  close_fixture(a,f);
  f=fixture(a);
  result=a->C_VerifyInit(f.session,&hmac,f.hmac);
  result=a->C_DecryptInit(f.session,&pad,f.aes);
  reset_output(&u,64);
  result=a->C_DecryptVerifyUpdate(f.session,NULL,32,u.bytes,&u.length);
  rv("C_DecryptVerifyUpdate","neg-null-part",result,CKR_ARGUMENTS_BAD);
  good = result==CKR_ARGUMENTS_BAD;
  reset_output(&q,64);
  follow=a->C_DecryptUpdate(f.session,(CK_BYTE_PTR)ptText,16,q.bytes,&q.length);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  follow=a->C_VerifyUpdate(f.session,(CK_BYTE_PTR)ptText,16);
  good &= follow==CKR_OPERATION_NOT_INITIALIZED;
  check("C_DecryptVerifyUpdate","neg-null-part",good);
  close_fixture(a,f);
}
static int want_legs(const char *which, const char *name) {
  return strcmp(which,"all")==0 || strcmp(which,name)==0;
}
static int want_ver(const char *only, const char *v) {
  return only==NULL || strcmp(only,v)==0;
}
static void run_legs(DualApi *a, const char *which) {
  printf("dual:version/%s legs=%s\n",ver,which);
  if (want_legs(which,"route")) {
    route_digest_encrypt(a);
    route_decrypt_digest(a);
    route_sign_encrypt(a);
    route_decrypt_verify(a);
  }
  if (want_legs(which,"equiv")) {
    equiv_digest_encrypt(a);
    equiv_decrypt_digest(a);
    equiv_sign_encrypt(a);
    equiv_decrypt_verify(a);
    equiv_final_nonaligned_digest(a);
    equiv_final_gcm_digest(a);
    equiv_final_nonaligned_verify(a);
    partial_final_nonaligned_digest(a);
    partial_final_gcm_digest(a);
    partial_final_nonaligned_verify(a);
    lifecycle_stale_link(a);
    lifecycle_peer_kind(a);
    lifecycle_zero_activity(a);
    lifecycle_staged_peer(a);
  }
  if (want_legs(which,"neg") || want_legs(which,"route")) {
    if (strcmp(ver,"3.2")==0) {
      neg_digest_encrypt(a);
      neg_decrypt_digest(a);
      neg_sign_encrypt(a);
      neg_decrypt_verify(a);
    } else {
      printf("dual:neg/%s legs=skip\n",ver);
    }
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
  if (!(strcmp(which,"all")==0 || strcmp(which,"route")==0 || strcmp(which,"equiv")==0 || strcmp(which,"neg")==0)) return 2;
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
    DualApi a;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    CK_RV result;
    snprintf(ver,sizeof(ver),"%s","2.40");
    result=getList(&list);
    rv("C_GetFunctionList","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !list) return 1;
    check("C_GetFunctionList","version",list->version.major==2 && list->version.minor==40);
    a=read_legacy(list);
    if (!a.C_DigestEncryptUpdate || !a.C_DecryptDigestUpdate || !a.C_SignEncryptUpdate || !a.C_DecryptVerifyUpdate) return 1;
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
    DualApi a;
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
    if (!a.C_DigestEncryptUpdate || !a.C_DecryptDigestUpdate || !a.C_SignEncryptUpdate || !a.C_DecryptVerifyUpdate) return 1;
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
  printf("dual:summary legs=%s failed=%d\n",which,failures);
  if (failures) return 1;
  printf("PASS: dual_routed (%s)\n",which);
  return 0;
}
