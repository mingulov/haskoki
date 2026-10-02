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

static int failures, proxy;
static int directProbe;
static unsigned minor;
static CK_SLOT_ID tokenSlot;
static char configPath[256];
static CK_BYTE aesBytes[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
static CK_BYTE iv[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static CK_BYTE plain[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
static CK_BYTE cipher[16] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
static CK_BYTE macBytes[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
static CK_BYTE witness[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
static CK_BYTE textBytes[8] = {'H','i',' ','T','h','e','r','e'};
static CK_MECHANISM cbc = {CKM_AES_CBC, iv, sizeof(iv)};
static CK_MECHANISM padded = {CKM_AES_CBC_PAD, iv, sizeof(iv)};
static CK_MECHANISM hmac = {CKM_SHA256_HMAC, NULL, 0};

typedef struct {
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CreateObject C_CreateObject;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_MessageEncryptInit C_MessageEncryptInit;
  CK_C_EncryptMessage C_EncryptMessage;
  CK_C_EncryptMessageBegin C_EncryptMessageBegin;
  CK_C_EncryptMessageNext C_EncryptMessageNext;
  CK_C_MessageEncryptFinal C_MessageEncryptFinal;
  CK_C_MessageDecryptInit C_MessageDecryptInit;
  CK_C_DecryptMessage C_DecryptMessage;
  CK_C_DecryptMessageBegin C_DecryptMessageBegin;
  CK_C_DecryptMessageNext C_DecryptMessageNext;
  CK_C_MessageDecryptFinal C_MessageDecryptFinal;
  CK_C_MessageSignInit C_MessageSignInit;
  CK_C_SignMessage C_SignMessage;
  CK_C_SignMessageBegin C_SignMessageBegin;
  CK_C_SignMessageNext C_SignMessageNext;
  CK_C_MessageSignFinal C_MessageSignFinal;
  CK_C_MessageVerifyInit C_MessageVerifyInit;
  CK_C_VerifyMessage C_VerifyMessage;
  CK_C_VerifyMessageBegin C_VerifyMessageBegin;
  CK_C_VerifyMessageNext C_VerifyMessageNext;
  CK_C_MessageVerifyFinal C_MessageVerifyFinal;
} MessageApi;
typedef struct { CK_SESSION_HANDLE session; CK_OBJECT_HANDLE aes, mac, noSign, noVerify; } Fixture;
typedef struct { CK_BYTE bytes[66]; CK_ULONG length; } Output;

static void check(const char *entry, const char *leg, int good) {
  printf("%s:%s/%s/3.%u check=%s\n",directProbe ? "topology:direct-only-message" : "message",entry,leg,minor,good ? "ok" : "FAIL");
  if (!good) ++failures;
}
static void rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  printf("%s:%s/%s/3.%u rv=0x%lx expected=0x%lx\n",directProbe ? "topology:direct-only-message" : "message",entry,leg,minor,got,want);
  if (got != want) ++failures;
}
static void reset_output(Output *o, CK_ULONG n) { memset(o->bytes,0xa5,sizeof(o->bytes)); o->length=n; }
static void output_length(const char *entry, const char *leg, const Output *o, CK_ULONG want) {
  printf("%s:%s/%s/3.%u length=%lu expected=%lu\n",directProbe ? "topology:direct-only-message" : "message",entry,leg,minor,o->length,want);
  if (o->length != want) ++failures;
}
static void untouched(const char *entry, const char *leg, const Output *o, CK_ULONG n) {
  int good = o->length == n;
  for (size_t i=0;i<sizeof(o->bytes);++i) good &= o->bytes[i] == 0xa5;
  check(entry,leg,good);
}
static void output_bytes(const char *entry, const char *leg, const Output *o, const CK_BYTE *want, CK_ULONG n) {
  int good = o->length == n && n <= 64;
  printf("%s:%s/%s/3.%u hex=",directProbe ? "topology:direct-only-message" : "message",entry,leg,minor);
  for (CK_ULONG i=0;i<o->length && i<64;++i) printf("%02x",o->bytes[i+1]);
  printf("\n");
  if (n <= 64) good &= memcmp(o->bytes+1,want,n) == 0;
  good &= o->bytes[0] == 0xa5;
  for (size_t i=(size_t)n+1;i<sizeof(o->bytes);++i) good &= o->bytes[i] == 0xa5;
  check(entry,leg,good);
}
static CK_OBJECT_HANDLE make_key(MessageApi *a, CK_SESSION_HANDLE session, CK_KEY_TYPE type, CK_BYTE *value, CK_ULONG n, CK_BBOOL enc, CK_BBOOL dec, CK_BBOOL sign, CK_BBOOL verify) {
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
static Fixture fixture(MessageApi *a) {
  Fixture f={0};
  CK_RV result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&f.session);
  rv("fixture","open",result,CKR_OK);
  if (result != CKR_OK) exit(1);
  f.aes=make_key(a,f.session,CKK_AES,aesBytes,16,CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);
  f.mac=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_TRUE);
  f.noSign=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_FALSE,CK_TRUE);
  f.noVerify=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_FALSE);
  return f;
}
static void close_fixture(MessageApi *a, Fixture f) { rv("fixture","close",a->C_CloseSession(f.session),CKR_OK); }
static void configure(void) {
  char path[]="/tmp/haskoki-message-config-XXXXXX";
  const char body[]="schema_version = 1\nprofile = \"real-crypto\"\n[storage]\nkind = \"memory\"\n[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\nprivate_library_context = true\n[trace]\nenabled = false\n";
  int fd=mkstemp(path);
  if (fd<0 || write(fd,body,sizeof(body)-1)!=(ssize_t)(sizeof(body)-1)) exit(2);
  close(fd);
  snprintf(configPath,sizeof(configPath),"%s",path);
  if (setenv("HASKOKI_CONFIG",configPath,1)!=0) exit(2);
}
static MessageApi read_common(CK_FUNCTION_LIST_3_0 *table) {
  MessageApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_GenerateKeyPair=table->C_GenerateKeyPair;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_Decrypt=table->C_Decrypt;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_SignInit=table->C_SignInit;
  a.C_Sign=table->C_Sign;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_Verify=table->C_Verify;
  a.C_MessageEncryptInit=table->C_MessageEncryptInit;
  a.C_EncryptMessage=table->C_EncryptMessage;
  a.C_EncryptMessageBegin=table->C_EncryptMessageBegin;
  a.C_EncryptMessageNext=table->C_EncryptMessageNext;
  a.C_MessageEncryptFinal=table->C_MessageEncryptFinal;
  a.C_MessageDecryptInit=table->C_MessageDecryptInit;
  a.C_DecryptMessage=table->C_DecryptMessage;
  a.C_DecryptMessageBegin=table->C_DecryptMessageBegin;
  a.C_DecryptMessageNext=table->C_DecryptMessageNext;
  a.C_MessageDecryptFinal=table->C_MessageDecryptFinal;
  a.C_MessageSignInit=table->C_MessageSignInit;
  a.C_SignMessage=table->C_SignMessage;
  a.C_SignMessageBegin=table->C_SignMessageBegin;
  a.C_SignMessageNext=table->C_SignMessageNext;
  a.C_MessageSignFinal=table->C_MessageSignFinal;
  a.C_MessageVerifyInit=table->C_MessageVerifyInit;
  a.C_VerifyMessage=table->C_VerifyMessage;
  a.C_VerifyMessageBegin=table->C_VerifyMessageBegin;
  a.C_VerifyMessageNext=table->C_VerifyMessageNext;
  a.C_MessageVerifyFinal=table->C_MessageVerifyFinal;
  check("C_MessageEncryptInit","slot-present",a.C_MessageEncryptInit != NULL);
  check("C_EncryptMessage","slot-present",a.C_EncryptMessage != NULL);
  check("C_EncryptMessageBegin","slot-present",a.C_EncryptMessageBegin != NULL);
  check("C_EncryptMessageNext","slot-present",a.C_EncryptMessageNext != NULL);
  check("C_MessageEncryptFinal","slot-present",a.C_MessageEncryptFinal != NULL);
  check("C_MessageDecryptInit","slot-present",a.C_MessageDecryptInit != NULL);
  check("C_DecryptMessage","slot-present",a.C_DecryptMessage != NULL);
  check("C_DecryptMessageBegin","slot-present",a.C_DecryptMessageBegin != NULL);
  check("C_DecryptMessageNext","slot-present",a.C_DecryptMessageNext != NULL);
  check("C_MessageDecryptFinal","slot-present",a.C_MessageDecryptFinal != NULL);
  check("C_MessageSignInit","slot-present",a.C_MessageSignInit != NULL);
  check("C_SignMessage","slot-present",a.C_SignMessage != NULL);
  check("C_SignMessageBegin","slot-present",a.C_SignMessageBegin != NULL);
  check("C_SignMessageNext","slot-present",a.C_SignMessageNext != NULL);
  check("C_MessageSignFinal","slot-present",a.C_MessageSignFinal != NULL);
  check("C_MessageVerifyInit","slot-present",a.C_MessageVerifyInit != NULL);
  check("C_VerifyMessage","slot-present",a.C_VerifyMessage != NULL);
  check("C_VerifyMessageBegin","slot-present",a.C_VerifyMessageBegin != NULL);
  check("C_VerifyMessageNext","slot-present",a.C_VerifyMessageNext != NULL);
  check("C_MessageVerifyFinal","slot-present",a.C_MessageVerifyFinal != NULL);
  check("C_GetMechanismList","slot-present",a.C_GetMechanismList != NULL);
  check("C_GetMechanismInfo","slot-present",a.C_GetMechanismInfo != NULL);
  check("C_GenerateKeyPair","slot-present",a.C_GenerateKeyPair != NULL);
  return a;
}
static MessageApi read_newest(CK_FUNCTION_LIST_3_2 *table) {
  MessageApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_GenerateKeyPair=table->C_GenerateKeyPair;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_Decrypt=table->C_Decrypt;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_SignInit=table->C_SignInit;
  a.C_Sign=table->C_Sign;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_Verify=table->C_Verify;
  a.C_MessageEncryptInit=table->C_MessageEncryptInit;
  a.C_EncryptMessage=table->C_EncryptMessage;
  a.C_EncryptMessageBegin=table->C_EncryptMessageBegin;
  a.C_EncryptMessageNext=table->C_EncryptMessageNext;
  a.C_MessageEncryptFinal=table->C_MessageEncryptFinal;
  a.C_MessageDecryptInit=table->C_MessageDecryptInit;
  a.C_DecryptMessage=table->C_DecryptMessage;
  a.C_DecryptMessageBegin=table->C_DecryptMessageBegin;
  a.C_DecryptMessageNext=table->C_DecryptMessageNext;
  a.C_MessageDecryptFinal=table->C_MessageDecryptFinal;
  a.C_MessageSignInit=table->C_MessageSignInit;
  a.C_SignMessage=table->C_SignMessage;
  a.C_SignMessageBegin=table->C_SignMessageBegin;
  a.C_SignMessageNext=table->C_SignMessageNext;
  a.C_MessageSignFinal=table->C_MessageSignFinal;
  a.C_MessageVerifyInit=table->C_MessageVerifyInit;
  a.C_VerifyMessage=table->C_VerifyMessage;
  a.C_VerifyMessageBegin=table->C_VerifyMessageBegin;
  a.C_VerifyMessageNext=table->C_VerifyMessageNext;
  a.C_MessageVerifyFinal=table->C_MessageVerifyFinal;
  check("C_MessageEncryptInit","slot-present",a.C_MessageEncryptInit != NULL);
  check("C_EncryptMessage","slot-present",a.C_EncryptMessage != NULL);
  check("C_EncryptMessageBegin","slot-present",a.C_EncryptMessageBegin != NULL);
  check("C_EncryptMessageNext","slot-present",a.C_EncryptMessageNext != NULL);
  check("C_MessageEncryptFinal","slot-present",a.C_MessageEncryptFinal != NULL);
  check("C_MessageDecryptInit","slot-present",a.C_MessageDecryptInit != NULL);
  check("C_DecryptMessage","slot-present",a.C_DecryptMessage != NULL);
  check("C_DecryptMessageBegin","slot-present",a.C_DecryptMessageBegin != NULL);
  check("C_DecryptMessageNext","slot-present",a.C_DecryptMessageNext != NULL);
  check("C_MessageDecryptFinal","slot-present",a.C_MessageDecryptFinal != NULL);
  check("C_MessageSignInit","slot-present",a.C_MessageSignInit != NULL);
  check("C_SignMessage","slot-present",a.C_SignMessage != NULL);
  check("C_SignMessageBegin","slot-present",a.C_SignMessageBegin != NULL);
  check("C_SignMessageNext","slot-present",a.C_SignMessageNext != NULL);
  check("C_MessageSignFinal","slot-present",a.C_MessageSignFinal != NULL);
  check("C_MessageVerifyInit","slot-present",a.C_MessageVerifyInit != NULL);
  check("C_VerifyMessage","slot-present",a.C_VerifyMessage != NULL);
  check("C_VerifyMessageBegin","slot-present",a.C_VerifyMessageBegin != NULL);
  check("C_VerifyMessageNext","slot-present",a.C_VerifyMessageNext != NULL);
  check("C_MessageVerifyFinal","slot-present",a.C_MessageVerifyFinal != NULL);
  check("C_GetMechanismList","slot-present",a.C_GetMechanismList != NULL);
  check("C_GetMechanismInfo","slot-present",a.C_GetMechanismInfo != NULL);
  check("C_GenerateKeyPair","slot-present",a.C_GenerateKeyPair != NULL);
  return a;
}
static void boundary_legs(MessageApi *a, int lifecycle, const char *phase);
static void encrypt_legs(MessageApi *a);
static void decrypt_legs(MessageApi *a);
static void sign_legs(MessageApi *a);
static void verify_legs(MessageApi *a);
static void extra_legs(MessageApi *a);
static void oversize_legs(MessageApi *a);
static void sweep_legs(MessageApi *a);

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (setvbuf(stdout,NULL,_IOLBF,0)!=0) return 2;
  const char *topology=getenv("HASKOKI_CONSUMER_TOPOLOGY");
  proxy=topology && strcmp(topology,"proxy")==0;
  configure();
  void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if (!module) { fprintf(stderr,"module could not load\n"); return 2; }
  CK_C_GetInterface getInterface=(CK_C_GetInterface)dlsym(module,"C_GetInterface");
  if (!getInterface) return 2;
  for (minor=0;minor<=2;++minor) {
    CK_VERSION version={3,(CK_BYTE)minor};
    CK_INTERFACE_PTR interface=NULL;
    CK_RV result=getInterface(NULL,&version,&interface,0);
    rv("C_GetInterface","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !interface || !interface->pFunctionList) return 1;
    MessageApi a;
    if (minor<2) {
      CK_FUNCTION_LIST_3_0 *table=(CK_FUNCTION_LIST_3_0 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==minor);
      a=read_common(table);
    } else {
      CK_FUNCTION_LIST_3_2 *table=(CK_FUNCTION_LIST_3_2 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==minor);
      a=read_newest(table);
    }
    if (failures) return 1;
    boundary_legs(&a,1,"pre-init");
    result=a.C_Initialize(NULL);
    rv("C_Initialize","live",result,CKR_OK);
    if (result != CKR_OK) return 1;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    result=a.C_GetSlotList(CK_TRUE,slots,&count);
    rv("C_GetSlotList","token-present",result,CKR_OK);
    if (result != CKR_OK || count==0 || count>16) return 1;
    tokenSlot=slots[0];
    boundary_legs(&a,0,"live");
    encrypt_legs(&a);
    decrypt_legs(&a);
    sign_legs(&a);
    verify_legs(&a);
    extra_legs(&a);
    sweep_legs(&a);
    if (!proxy) oversize_legs(&a);
    rv("C_Finalize","end",a.C_Finalize(NULL),CKR_OK);
    boundary_legs(&a,1,"post-finalize");
  }
  dlclose(module);
  unlink(configPath);
  if (failures) return 1;
  puts("PASS: message_routed");
  return 0;
}

static CK_RV probe_C_MessageEncryptInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageEncryptInit(f->session,&cbc,f->aes);
    case 1: return a->C_MessageEncryptInit(f->session,NULL,f->aes);
    case 2: return a->C_MessageEncryptInit(f->session,&badMechanism,f->aes);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessage(f->session,iv,16,NULL,0,plain,16,o->bytes+1,&o->length);
    case 1: return a->C_EncryptMessage(f->session,iv,16,NULL,0,plain,16,o->bytes+1,NULL);
    case 2: return a->C_EncryptMessage(f->session,NULL,1,NULL,0,plain,16,o->bytes+1,&o->length);
    case 3: return a->C_EncryptMessage(f->session,iv,16,NULL,1,plain,16,o->bytes+1,&o->length);
    case 4: return a->C_EncryptMessage(f->session,iv,16,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessageBegin(f->session,iv,16,NULL,0);
    case 1: return a->C_EncryptMessageBegin(f->session,NULL,1,NULL,0);
    case 2: return a->C_EncryptMessageBegin(f->session,iv,16,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 1: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,NULL,CKF_END_OF_MESSAGE);
    case 2: return a->C_EncryptMessageNext(f->session,NULL,1,plain,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 3: return a->C_EncryptMessageNext(f->session,iv,16,NULL,1,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 4: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,&o->length,2);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageEncryptFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageEncryptFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageDecryptInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageDecryptInit(f->session,&cbc,f->aes);
    case 1: return a->C_MessageDecryptInit(f->session,NULL,f->aes);
    case 2: return a->C_MessageDecryptInit(f->session,&badMechanism,f->aes);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessage(f->session,iv,16,NULL,0,cipher,16,o->bytes+1,&o->length);
    case 1: return a->C_DecryptMessage(f->session,iv,16,NULL,0,cipher,16,o->bytes+1,NULL);
    case 2: return a->C_DecryptMessage(f->session,NULL,1,NULL,0,cipher,16,o->bytes+1,&o->length);
    case 3: return a->C_DecryptMessage(f->session,iv,16,NULL,1,cipher,16,o->bytes+1,&o->length);
    case 4: return a->C_DecryptMessage(f->session,iv,16,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessageBegin(f->session,iv,16,NULL,0);
    case 1: return a->C_DecryptMessageBegin(f->session,NULL,1,NULL,0);
    case 2: return a->C_DecryptMessageBegin(f->session,iv,16,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 1: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,NULL,CKF_END_OF_MESSAGE);
    case 2: return a->C_DecryptMessageNext(f->session,NULL,1,cipher,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 3: return a->C_DecryptMessageNext(f->session,iv,16,NULL,1,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 4: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,&o->length,2);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageDecryptFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageDecryptFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageSignInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageSignInit(f->session,&hmac,f->mac);
    case 1: return a->C_MessageSignInit(f->session,NULL,f->mac);
    case 2: return a->C_MessageSignInit(f->session,&badMechanism,f->mac);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessage(f->session,NULL,0,textBytes,8,o->bytes+1,&o->length);
    case 1: return a->C_SignMessage(f->session,NULL,0,textBytes,8,o->bytes+1,NULL);
    case 2: return a->C_SignMessage(f->session,NULL,1,textBytes,8,o->bytes+1,&o->length);
    case 3: return a->C_SignMessage(f->session,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessageBegin(f->session,NULL,0);
    case 1: return a->C_SignMessageBegin(f->session,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessageNext(f->session,NULL,0,textBytes,8,o->bytes+1,&o->length);
    case 1: return a->C_SignMessageNext(f->session,NULL,1,textBytes,8,o->bytes+1,&o->length);
    case 2: return a->C_SignMessageNext(f->session,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageSignFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageSignFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageVerifyInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageVerifyInit(f->session,&hmac,f->mac);
    case 1: return a->C_MessageVerifyInit(f->session,NULL,f->mac);
    case 2: return a->C_MessageVerifyInit(f->session,&badMechanism,f->mac);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessage(f->session,NULL,0,textBytes,8,witness,32);
    case 1: return a->C_VerifyMessage(f->session,NULL,1,textBytes,8,witness,32);
    case 2: return a->C_VerifyMessage(f->session,NULL,0,NULL,1,witness,32);
    case 3: return a->C_VerifyMessage(f->session,NULL,0,textBytes,8,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessageBegin(f->session,NULL,0);
    case 1: return a->C_VerifyMessageBegin(f->session,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessageNext(f->session,NULL,0,textBytes,8,witness,32);
    case 1: return a->C_VerifyMessageNext(f->session,NULL,1,textBytes,8,witness,32);
    case 2: return a->C_VerifyMessageNext(f->session,NULL,0,NULL,1,witness,32);
    case 3: return a->C_VerifyMessageNext(f->session,NULL,0,textBytes,8,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageVerifyFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageVerifyFinal(f->session);
    default: exit(2);
  }
}
typedef CK_RV (*Probe)(MessageApi *,Fixture *,unsigned,Output *);
static int boundary_shim_refusal(Probe call, unsigned shape, int lifecycle, const char *phase, CK_RV *want) {
  if (!lifecycle) return 0;
  /* Canonical proxy a48b60ba54b0163f4999c1e4fc0514bf7dc01681:
     crates/shim/src/dispatch/general/message_crypto.rs validates Init
     mechanisms before with_client. helpers.rs:356-368 reads the registry;
     crates/shim/src/state.rs:26-27 panics before its first initialization,
     and helpers.rs:304-311 maps that panic to CKR_GENERAL_ERROR.
     The registry survives Finalize, so only the first pre-init is cold. */
  int init = call==probe_C_MessageEncryptInit || call==probe_C_MessageDecryptInit
    || call==probe_C_MessageSignInit || call==probe_C_MessageVerifyInit;
  if (minor==0 && strcmp(phase,"pre-init")==0 && init && (shape==0 || shape==2)) {
    *want=CKR_GENERAL_ERROR;
    return 1;
  }
  /* In the same message_crypto.rs, the five required output-length
     guards and helpers.rs:233-246 parameter guards precede with_client
     (helpers.rs:23-34). SignMessageNext uses the parameter guard only
     when the length pointer requests a signature. No call is forwarded. */
  int output = call==probe_C_EncryptMessage || call==probe_C_DecryptMessage
    || call==probe_C_EncryptMessageNext || call==probe_C_DecryptMessageNext
    || call==probe_C_SignMessage;
  if ((output && (shape==1 || shape==2)) || (call==probe_C_SignMessageNext && shape==1)) {
    *want=CKR_ARGUMENTS_BAD;
    return 1;
  }
  return 0;
}
static void boundary_legs(MessageApi *a, int lifecycle, const char *phase) {
  static const struct { const char *name; Probe call; unsigned count; const char *labels[6]; } entries[] = {
    {"C_MessageEncryptInit",probe_C_MessageEncryptInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_EncryptMessage",probe_C_EncryptMessage,5,{"well-shaped","missing-length","bad-pParameter","bad-pAssociatedData","bad-pPlaintext"}},
    {"C_EncryptMessageBegin",probe_C_EncryptMessageBegin,3,{"well-shaped","bad-pParameter","bad-pAssociatedData"}},
    {"C_EncryptMessageNext",probe_C_EncryptMessageNext,5,{"well-shaped","missing-length","bad-pParameter","bad-pPlaintextPart","unknown-flags"}},
    {"C_MessageEncryptFinal",probe_C_MessageEncryptFinal,1,{"well-shaped"}},
    {"C_MessageDecryptInit",probe_C_MessageDecryptInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_DecryptMessage",probe_C_DecryptMessage,5,{"well-shaped","missing-length","bad-pParameter","bad-pAssociatedData","bad-pCiphertext"}},
    {"C_DecryptMessageBegin",probe_C_DecryptMessageBegin,3,{"well-shaped","bad-pParameter","bad-pAssociatedData"}},
    {"C_DecryptMessageNext",probe_C_DecryptMessageNext,5,{"well-shaped","missing-length","bad-pParameter","bad-pCiphertextPart","unknown-flags"}},
    {"C_MessageDecryptFinal",probe_C_MessageDecryptFinal,1,{"well-shaped"}},
    {"C_MessageSignInit",probe_C_MessageSignInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_SignMessage",probe_C_SignMessage,4,{"well-shaped","missing-length","bad-pParameter","bad-pData"}},
    {"C_SignMessageBegin",probe_C_SignMessageBegin,2,{"well-shaped","bad-pParameter"}},
    {"C_SignMessageNext",probe_C_SignMessageNext,3,{"well-shaped","bad-pParameter","bad-pDataPart"}},
    {"C_MessageSignFinal",probe_C_MessageSignFinal,1,{"well-shaped"}},
    {"C_MessageVerifyInit",probe_C_MessageVerifyInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_VerifyMessage",probe_C_VerifyMessage,4,{"well-shaped","bad-pParameter","bad-pData","bad-pSignature"}},
    {"C_VerifyMessageBegin",probe_C_VerifyMessageBegin,2,{"well-shaped","bad-pParameter"}},
    {"C_VerifyMessageNext",probe_C_VerifyMessageNext,4,{"well-shaped","bad-pParameter","bad-pDataPart","bad-pSignature"}},
    {"C_MessageVerifyFinal",probe_C_MessageVerifyFinal,1,{"well-shaped"}},
  };
  for (size_t i=0;i<sizeof(entries)/sizeof(entries[0]);++i) {
    for (unsigned shape=0;shape<entries[i].count;++shape) {
      unsigned variants=lifecycle ? 1U : (shape ? 2U : 1U);
      for (unsigned badSession=0;badSession<variants;++badSession) {
        Fixture owned={0};
        if (!lifecycle) owned=fixture(a);
        Fixture f=owned;
        if (lifecycle || badSession || shape==0) f.session=~0UL;
        Output o; reset_output(&o,777);
        char leg[160];
        snprintf(leg,sizeof(leg),"%s-%s-%s",phase,entries[i].labels[shape],f.session==~0UL ? "invalid-session" : "valid-session");
        CK_RV want=lifecycle ? CKR_CRYPTOKI_NOT_INITIALIZED : shape ? CKR_ARGUMENTS_BAD : CKR_SESSION_HANDLE_INVALID;
        CK_RV got=entries[i].call(a,&f,shape,&o), shimWant;
        if (boundary_shim_refusal(entries[i].call,shape,lifecycle,phase,&shimWant)) {
          CK_RV exact=proxy ? shimWant : want;
          printf("topology:message-shim-refusal:%s/%s/3.%u rv=0x%lx expected=0x%lx\n",entries[i].name,leg,minor,got,exact);
          if (got != exact) ++failures;
        } else {
          rv(entries[i].name,leg,got,want);
        }
        untouched(entries[i].name,leg,&o,777);
        if (!lifecycle) close_fixture(a,owned);
      }
    }
  }
}

static void encrypt_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  CK_MECHANISM unknown={0xffffffffUL,NULL,0};
  CK_BYTE changedIv[16]={0};
  reset_output(&o,777);
  rv("C_EncryptMessage","no-init",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_EncryptMessage","no-init",&o,777);
  rv("C_EncryptMessageBegin","no-init",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_EncryptMessageNext","no-begin",a->C_EncryptMessageNext(f.session,NULL,0,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_EncryptMessageNext","no-begin",&o,777);
  rv("C_MessageEncryptFinal","no-init",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageEncryptInit","bad-key",a->C_MessageEncryptInit(f.session,&cbc,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageEncryptInit","unknown-mechanism",a->C_MessageEncryptInit(f.session,&unknown,f.aes),CKR_MECHANISM_INVALID);
  rv("C_MessageEncryptInit","init-cbc",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageEncryptInit","duplicate-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_EncryptInit","message-collision",a->C_EncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-cbc-query",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  output_length("C_EncryptMessage","one-cbc-query",&o,16);
  untouched("C_EncryptMessage","one-cbc-query",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_EncryptMessage","one-cbc-repeat-query",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  output_length("C_EncryptMessage","one-cbc-repeat-query",&o,16);
  untouched("C_EncryptMessage","one-cbc-repeat-query",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-repeat-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessage","one-cbc-zero-capacity",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessage","one-cbc-zero-capacity",&o,16);
  untouched("C_EncryptMessage","one-cbc-zero-capacity",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-zero-capacity-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_EncryptMessage","one-cbc-short",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessage","one-cbc-short",&o,16);
  untouched("C_EncryptMessage","one-cbc-short",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-short-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-cbc-exact-malformed-recall",a->C_EncryptMessage(f.session,NULL,1,NULL,0,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessage","one-cbc-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessage","one-cbc-exact",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","one-cbc-exact",&o,cipher,16);
  reset_output(&o,16);
  rv("C_EncryptMessage","second-message",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","second-message",&o,cipher,16);
  rv("C_MessageEncryptFinal","final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageEncryptFinal","second-final",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_EncryptInit","released-slot",a->C_EncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageEncryptInit","classic-collision",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_EncryptMessageBegin","classic-only",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,16);
  rv("C_Encrypt","classic-completion",a->C_Encrypt(f.session,plain,16,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageEncryptInit","multipart-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_EncryptMessageBegin","begin-iv",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_EncryptMessage","while-open",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_EncryptMessage","while-open",&o,777);
  rv("C_MessageEncryptFinal","open-message",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_EncryptUpdate","message-mixing",a->C_EncryptUpdate(f.session,plain,0,o.bytes+1,&o.length),CKR_GENERAL_ERROR);
  untouched("C_EncryptUpdate","message-mixing",&o,777);
  reset_output(&o,733);
  rv("C_EncryptMessageNext","non-ending-query",a->C_EncryptMessageNext(f.session,NULL,0,plain,7,NULL,&o.length,0),CKR_OK);
  output_length("C_EncryptMessageNext","non-ending-query",&o,0);
  rv("C_MessageEncryptFinal","continuation-query-open",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessageNext","part-cbc",a->C_EncryptMessageNext(f.session,NULL,0,plain,7,o.bytes+1,&o.length,0),CKR_OK);
  untouched("C_EncryptMessageNext","zero-output-continuation",&o,0);
  rv("C_EncryptMessageBegin","second-begin-keeps-part",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessageNext","terminal-query",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_EncryptMessageNext","terminal-query",&o,16);
  untouched("C_EncryptMessageNext","terminal-query",&o,16);
  rv("C_MessageEncryptFinal","terminal-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_EncryptMessageNext","terminal-repeat-query",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_EncryptMessageNext","terminal-repeat-query",&o,16);
  untouched("C_EncryptMessageNext","terminal-repeat-query",&o,16);
  rv("C_MessageEncryptFinal","terminal-repeat-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessageNext","terminal-zero-capacity",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessageNext","terminal-zero-capacity",&o,16);
  untouched("C_EncryptMessageNext","terminal-zero-capacity",&o,16);
  rv("C_MessageEncryptFinal","terminal-zero-capacity-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_EncryptMessageNext","terminal-short",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessageNext","terminal-short",&o,16);
  untouched("C_EncryptMessageNext","terminal-short",&o,16);
  rv("C_MessageEncryptFinal","terminal-short-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessageNext","terminal-exact-malformed-recall",a->C_EncryptMessageNext(f.session,NULL,1,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessageNext","terminal-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","terminal-exact",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","terminal-exact",&o,cipher,16);
  rv("C_MessageEncryptFinal","multipart-final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageEncryptInit","recall-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&o,1);
  rv("C_EncryptMessage","recall-stage",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  rv("C_MessageEncryptFinal","recall-stage-busy",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","malformed-recall",a->C_EncryptMessage(f.session,NULL,1,NULL,0,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessage","malformed-recall",&o,777);
  rv("C_Encrypt","staged-message-mixing",a->C_Encrypt(f.session,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_Encrypt","staged-message-mixing",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessage","recall-after-malformed",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","recall-after-malformed",&o,cipher,16);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-byte-unpadded",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,1,o.bytes+1,&o.length),CKR_DATA_LEN_RANGE);
  untouched("C_EncryptMessage","one-byte-unpadded",&o,777);
  rv("C_EncryptMessageBegin","after-one-byte-refusal",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  rv("C_EncryptMessageNext","unaligned-end",a->C_EncryptMessageNext(f.session,NULL,0,plain,1,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_DATA_LEN_RANGE);
  untouched("C_EncryptMessageNext","unaligned-end",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","repair-alignment",a->C_EncryptMessageNext(f.session,NULL,0,plain+1,15,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","repair-alignment",&o,cipher,16);
  rv("C_EncryptMessageBegin","empty-parameter-aad",a->C_EncryptMessageBegin(f.session,NULL,0,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","supply-iv-at-end",a->C_EncryptMessageNext(f.session,iv,16,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","supply-iv-at-end",&o,cipher,16);
  rv("C_EncryptMessageBegin","replacement-iv-begin",a->C_EncryptMessageBegin(f.session,changedIv,16,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","replace-iv-at-end",a->C_EncryptMessageNext(f.session,iv,16,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","replace-iv-at-end",&o,cipher,16);
  rv("C_MessageEncryptFinal","last-final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageEncryptInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_EncryptMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageEncryptFinal;
  check("C_MessageEncryptInit","no-query",noQueryInit!=NULL);
  check("C_EncryptMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageEncryptFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}

static void decrypt_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  CK_MECHANISM unknown={0xffffffffUL,NULL,0};
  CK_BYTE changedIv[16]={0};
  reset_output(&o,777);
  rv("C_DecryptMessage","no-init",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_DecryptMessage","no-init",&o,777);
  rv("C_DecryptMessageBegin","no-init",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_DecryptMessageNext","no-begin",a->C_DecryptMessageNext(f.session,NULL,0,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_DecryptMessageNext","no-begin",&o,777);
  rv("C_MessageDecryptFinal","no-init",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageDecryptInit","bad-key",a->C_MessageDecryptInit(f.session,&cbc,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageDecryptInit","unknown-mechanism",a->C_MessageDecryptInit(f.session,&unknown,f.aes),CKR_MECHANISM_INVALID);
  rv("C_MessageDecryptInit","init-cbc",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","duplicate-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_DecryptInit","message-collision",a->C_DecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","one-cbc-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  output_length("C_DecryptMessage","one-cbc-query",&o,16);
  untouched("C_DecryptMessage","one-cbc-query",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_DecryptMessage","one-cbc-repeat-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  output_length("C_DecryptMessage","one-cbc-repeat-query",&o,16);
  untouched("C_DecryptMessage","one-cbc-repeat-query",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-repeat-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessage","one-cbc-zero-capacity",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessage","one-cbc-zero-capacity",&o,16);
  untouched("C_DecryptMessage","one-cbc-zero-capacity",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-zero-capacity-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_DecryptMessage","one-cbc-short",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessage","one-cbc-short",&o,16);
  untouched("C_DecryptMessage","one-cbc-short",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-short-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","one-cbc-exact-malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessage","one-cbc-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessage","one-cbc-exact",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","one-cbc-exact",&o,plain,16);
  reset_output(&o,16);
  rv("C_DecryptMessage","second-message",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","second-message",&o,plain,16);
  rv("C_MessageDecryptFinal","final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptFinal","second-final",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_DecryptInit","released-slot",a->C_DecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","classic-collision",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_DecryptMessageBegin","classic-only",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,16);
  rv("C_Decrypt","classic-completion",a->C_Decrypt(f.session,cipher,16,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageDecryptInit","multipart-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_DecryptMessageBegin","begin-iv",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_DecryptMessage","while-open",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_DecryptMessage","while-open",&o,777);
  rv("C_MessageDecryptFinal","open-message",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_DecryptUpdate","message-mixing",a->C_DecryptUpdate(f.session,cipher,0,o.bytes+1,&o.length),CKR_GENERAL_ERROR);
  untouched("C_DecryptUpdate","message-mixing",&o,777);
  reset_output(&o,733);
  rv("C_DecryptMessageNext","non-ending-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher,8,NULL,&o.length,0),CKR_OK);
  output_length("C_DecryptMessageNext","non-ending-query",&o,0);
  rv("C_MessageDecryptFinal","continuation-query-open",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessageNext","part-cbc",a->C_DecryptMessageNext(f.session,NULL,0,cipher,8,o.bytes+1,&o.length,0),CKR_OK);
  untouched("C_DecryptMessageNext","zero-output-continuation",&o,0);
  rv("C_DecryptMessageBegin","second-begin-keeps-part",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessageNext","terminal-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_DecryptMessageNext","terminal-query",&o,16);
  untouched("C_DecryptMessageNext","terminal-query",&o,16);
  rv("C_MessageDecryptFinal","terminal-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_DecryptMessageNext","terminal-repeat-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_DecryptMessageNext","terminal-repeat-query",&o,16);
  untouched("C_DecryptMessageNext","terminal-repeat-query",&o,16);
  rv("C_MessageDecryptFinal","terminal-repeat-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessageNext","terminal-zero-capacity",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessageNext","terminal-zero-capacity",&o,16);
  untouched("C_DecryptMessageNext","terminal-zero-capacity",&o,16);
  rv("C_MessageDecryptFinal","terminal-zero-capacity-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_DecryptMessageNext","terminal-short",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessageNext","terminal-short",&o,16);
  untouched("C_DecryptMessageNext","terminal-short",&o,16);
  rv("C_MessageDecryptFinal","terminal-short-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessageNext","terminal-exact-malformed-recall",a->C_DecryptMessageNext(f.session,NULL,1,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessageNext","terminal-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","terminal-exact",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","terminal-exact",&o,plain,16);
  rv("C_MessageDecryptFinal","multipart-final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptInit","recall-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&o,1);
  rv("C_DecryptMessage","recall-stage",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  rv("C_MessageDecryptFinal","recall-stage-busy",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessage","malformed-recall",&o,777);
  rv("C_Decrypt","staged-message-mixing",a->C_Decrypt(f.session,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_Decrypt","staged-message-mixing",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessage","recall-after-malformed",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","recall-after-malformed",&o,plain,16);
  rv("C_DecryptMessageBegin","empty-parameter-aad",a->C_DecryptMessageBegin(f.session,NULL,0,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","supply-iv-at-end",a->C_DecryptMessageNext(f.session,iv,16,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","supply-iv-at-end",&o,plain,16);
  rv("C_DecryptMessageBegin","replacement-iv-begin",a->C_DecryptMessageBegin(f.session,changedIv,16,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","replace-iv-at-end",a->C_DecryptMessageNext(f.session,iv,16,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","replace-iv-at-end",&o,plain,16);
  rv("C_MessageDecryptFinal","last-final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageDecryptInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_DecryptMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageDecryptFinal;
  check("C_MessageDecryptInit","no-query",noQueryInit!=NULL);
  check("C_DecryptMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageDecryptFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}

static void sign_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  reset_output(&o,777);
  rv("C_SignMessage","no-init",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_SignMessage","no-init",&o,777);
  rv("C_SignMessageBegin","no-init",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_SignMessageNext","no-begin",a->C_SignMessageNext(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_SignMessageNext","no-begin",&o,777);
  rv("C_MessageSignFinal","missing-context",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageSignInit","bad-key",a->C_MessageSignInit(f.session,&hmac,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageSignInit","denied-sign-usage",a->C_MessageSignInit(f.session,&hmac,f.noSign),CKR_KEY_FUNCTION_NOT_PERMITTED);
  rv("C_MessageSignInit","init-hmac",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageSignInit","duplicate-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_SignInit","message-collision",a->C_SignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessage","one-hmac-query",a->C_SignMessage(f.session,NULL,0,textBytes,8,NULL,&o.length),CKR_OK);
  output_length("C_SignMessage","one-hmac-query",&o,32);
  untouched("C_SignMessage","one-hmac-query",&o,32);
  rv("C_MessageSignFinal","one-hmac-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_SignMessage","one-hmac-repeat-query",a->C_SignMessage(f.session,NULL,0,textBytes,8,NULL,&o.length),CKR_OK);
  output_length("C_SignMessage","one-hmac-repeat-query",&o,32);
  untouched("C_SignMessage","one-hmac-repeat-query",&o,32);
  rv("C_MessageSignFinal","one-hmac-repeat-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_SignMessage","one-hmac-zero-capacity",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessage","one-hmac-zero-capacity",&o,32);
  untouched("C_SignMessage","one-hmac-zero-capacity",&o,32);
  rv("C_MessageSignFinal","one-hmac-zero-capacity-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,31);
  rv("C_SignMessage","one-hmac-short",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessage","one-hmac-short",&o,32);
  untouched("C_SignMessage","one-hmac-short",&o,32);
  rv("C_MessageSignFinal","one-hmac-short-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessage","one-hmac-exact-malformed-recall",a->C_SignMessage(f.session,NULL,1,textBytes,8,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessage","one-hmac-exact-malformed-recall",&o,777);
  reset_output(&o,32);
  rv("C_SignMessage","one-hmac-exact",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessage","one-hmac-exact",&o,witness,32);
  reset_output(&o,32);
  rv("C_SignMessage","second-message",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessage","second-message",&o,witness,32);
  rv("C_MessageSignFinal","final-idle",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_SignInit","released-slot",a->C_SignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageSignInit","classic-collision",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageBegin","classic-only",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,32);
  rv("C_Sign","classic-completion",a->C_Sign(f.session,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageSignInit","multipart-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_SignMessageBegin","begin-hmac",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_SignMessage","while-open",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_SignMessage","while-open",&o,777);
  rv("C_MessageSignFinal","open-message",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageNext","absent-output-and-length",a->C_SignMessageNext(f.session,NULL,0,NULL,0,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","ignored-present-output",a->C_SignMessageNext(f.session,NULL,0,textBytes,3,o.bytes+1,NULL),CKR_OK);
  untouched("C_SignMessageNext","ignored-present-output",&o,777);
  rv("C_SignMessageBegin","duplicate-begin-keeps-part",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageNext","null-part-nonzero",a->C_SignMessageNext(f.session,NULL,0,NULL,1,o.bytes+1,NULL),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessageNext","null-part-nonzero",&o,777);
  reset_output(&o,777);
  rv("C_SignMessageNext","part-hmac-query",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,NULL,&o.length),CKR_OK);
  output_length("C_SignMessageNext","part-hmac-query",&o,32);
  untouched("C_SignMessageNext","part-hmac-query",&o,32);
  rv("C_MessageSignFinal","part-hmac-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_SignMessageNext","part-hmac-repeat-query",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,NULL,&o.length),CKR_OK);
  output_length("C_SignMessageNext","part-hmac-repeat-query",&o,32);
  untouched("C_SignMessageNext","part-hmac-repeat-query",&o,32);
  rv("C_MessageSignFinal","part-hmac-repeat-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_SignMessageNext","part-hmac-zero-capacity",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessageNext","part-hmac-zero-capacity",&o,32);
  untouched("C_SignMessageNext","part-hmac-zero-capacity",&o,32);
  rv("C_MessageSignFinal","part-hmac-zero-capacity-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,31);
  rv("C_SignMessageNext","part-hmac-short",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessageNext","part-hmac-short",&o,32);
  untouched("C_SignMessageNext","part-hmac-short",&o,32);
  rv("C_MessageSignFinal","part-hmac-short-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessageNext","part-hmac-exact-malformed-recall",a->C_SignMessageNext(f.session,NULL,1,textBytes+3,5,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessageNext","part-hmac-exact-malformed-recall",&o,777);
  reset_output(&o,32);
  rv("C_SignMessageNext","part-hmac-exact",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessageNext","part-hmac-exact",&o,witness,32);
  rv("C_MessageSignFinal","multipart-final-idle",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_MessageSignFinal","second-final",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageSignInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG)=a->C_SignMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageSignFinal;
  check("C_MessageSignInit","no-query",noQueryInit!=NULL);
  check("C_SignMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageSignFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}

static void verify_legs(MessageApi *a) {
  Fixture f=fixture(a);
  CK_BYTE badWitness[32]; memcpy(badWitness,witness,32); badWitness[0]^=1;
  rv("C_VerifyMessage","no-init",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_VerifyMessageBegin","no-init",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_VerifyMessageNext","no-begin",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyFinal","missing-context",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyInit","bad-key",a->C_MessageVerifyInit(f.session,&hmac,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageVerifyInit","denied-verify-usage",a->C_MessageVerifyInit(f.session,&hmac,f.noVerify),CKR_KEY_FUNCTION_NOT_PERMITTED);
  rv("C_MessageVerifyInit","init-hmac",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","duplicate-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyInit","message-collision",a->C_VerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessage","one-hmac",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_VerifyMessage","flipped-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,badWitness,32),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessage","valid-after-invalid",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_VerifyMessage","null-empty-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,NULL,0),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessage","present-empty-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,0),CKR_SIGNATURE_INVALID);
  rv("C_MessageVerifyFinal","final-idle-after-invalid",a->C_MessageVerifyFinal(f.session),CKR_OK);
  rv("C_VerifyInit","released-slot",a->C_VerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","classic-collision",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessageBegin","classic-only",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_Verify","classic-completion",a->C_Verify(f.session,textBytes,8,witness,32),CKR_OK);
  rv("C_MessageVerifyInit","multipart-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_VerifyMessageBegin","begin-hmac",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageBegin","duplicate-begin",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_ACTIVE);
  rv("C_MessageVerifyFinal","open-message",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessage","while-open",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessageNext","absent-empty-witness",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,3,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","absent-nonzero-witness",a->C_VerifyMessageNext(f.session,NULL,0,textBytes+3,5,NULL,1),CKR_ARGUMENTS_BAD);
  rv("C_VerifyMessageNext","part-hmac",a->C_VerifyMessageNext(f.session,NULL,0,textBytes+3,5,witness,32),CKR_OK);
  rv("C_VerifyMessageBegin","begin-again",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","present-zero-ends",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,0),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessageBegin","begin-after-empty-mismatch",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","flipped-witness-ends",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,badWitness,32),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessageBegin","begin-after-flipped-mismatch",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","recovered-verdict",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_MessageVerifyFinal","final-idle",a->C_MessageVerifyFinal(f.session),CKR_OK);
  rv("C_MessageVerifyFinal","second-final",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageVerifyInit;
  CK_RV (*noQueryOne)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_VerifyMessage;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG)=a->C_VerifyMessageBegin;
  CK_RV (*noQueryNext)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_VerifyMessageNext;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageVerifyFinal;
  check("C_MessageVerifyInit","no-query",noQueryInit!=NULL);
  check("C_VerifyMessage","no-query",noQueryOne!=NULL);
  check("C_VerifyMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_VerifyMessageNext","no-query",noQueryNext!=NULL);
  check("C_MessageVerifyFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}

static void extra_legs(MessageApi *a) {
  Fixture f=fixture(a), reference=fixture(a);
  Output encrypted, decoded, classic;
  CK_BYTE abc[3]={'a','b','c'}, zero[16]={0}, presentEmpty=0;
  rv("C_MessageEncryptInit","pad-init",a->C_MessageEncryptInit(f.session,&padded,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","pad-init",a->C_MessageDecryptInit(f.session,&padded,f.aes),CKR_OK);
  for (unsigned shape=0;shape<3;++shape) {
    CK_BYTE *input=shape==0 ? abc : shape==1 ? NULL : &presentEmpty;
    CK_ULONG n=shape==0 ? 3 : 0;
    const char *leg=shape==0 ? "pad-abc" : shape==1 ? "pad-empty-null" : "pad-empty-present";
    reset_output(&classic,64);
    rv("C_EncryptInit",leg,a->C_EncryptInit(reference.session,&padded,reference.aes),CKR_OK);
    rv("C_Encrypt",leg,a->C_Encrypt(reference.session,input,n,classic.bytes+1,&classic.length),CKR_OK);
    reset_output(&encrypted,64);
    rv("C_EncryptMessage",leg,a->C_EncryptMessage(f.session,iv,16,NULL,0,input,n,encrypted.bytes+1,&encrypted.length),CKR_OK);
    output_bytes("C_EncryptMessage",leg,&encrypted,classic.bytes+1,classic.length);
    rv("C_DecryptInit",leg,a->C_DecryptInit(reference.session,&padded,reference.aes),CKR_OK);
    reset_output(&classic,64);
    rv("C_Decrypt",leg,a->C_Decrypt(reference.session,encrypted.bytes+1,encrypted.length,classic.bytes+1,&classic.length),CKR_OK);
    output_bytes("C_Decrypt",leg,&classic,input ? input : &presentEmpty,n);
    if (n==0) {
      reset_output(&decoded,999);
      rv("C_DecryptMessage","empty-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,NULL,&decoded.length),CKR_OK);
      untouched("C_DecryptMessage","empty-query",&decoded,0);
      rv("C_MessageDecryptFinal","empty-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
      reset_output(&decoded,1);
      rv("C_DecryptMessage","empty-query-repeat",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,NULL,&decoded.length),CKR_OK);
      untouched("C_DecryptMessage","empty-query-repeat",&decoded,0);
      rv("C_MessageDecryptFinal","empty-repeat-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
      reset_output(&decoded,777);
      rv("C_DecryptMessage","empty-malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_ARGUMENTS_BAD);
      untouched("C_DecryptMessage","empty-malformed-recall",&decoded,777);
    }
    reset_output(&decoded,n);
    rv("C_DecryptMessage",leg,a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_DecryptMessage",leg,&decoded,input ? input : &presentEmpty,n);
    rv("C_MessageDecryptFinal","after-delivery",a->C_MessageDecryptFinal(f.session),CKR_OK);
    rv("C_MessageDecryptInit","next-pad-context",a->C_MessageDecryptInit(f.session,&padded,f.aes),CKR_OK);
  }
  /* Deterministic invalid padding: unpadded encryption of an all-zero block. */
  rv("C_EncryptInit","bad-padding-source",a->C_EncryptInit(reference.session,&cbc,reference.aes),CKR_OK);
  reset_output(&classic,16);
  rv("C_Encrypt","bad-padding-source",a->C_Encrypt(reference.session,zero,16,classic.bytes+1,&classic.length),CKR_OK);
  reset_output(&decoded,777);
  rv("C_DecryptMessage","deterministic-bad-padding",a->C_DecryptMessage(f.session,iv,16,NULL,0,classic.bytes+1,16,decoded.bytes+1,&decoded.length),CKR_ENCRYPTED_DATA_INVALID);
  untouched("C_DecryptMessage","deterministic-bad-padding",&decoded,777);
  reset_output(&decoded,0);
  rv("C_DecryptMessage","valid-after-padding-failure",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_OK);
  untouched("C_DecryptMessage","valid-empty-after-padding-failure",&decoded,0);
  rv("C_MessageEncryptFinal","pad-final",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptFinal","pad-final",a->C_MessageDecryptFinal(f.session),CKR_OK);

  /* Sibling slots are independently usable and independently finalized. */
  rv("C_MessageEncryptInit","sibling-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","sibling-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&encrypted,16);
  rv("C_EncryptMessage","sibling-one",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,encrypted.bytes+1,&encrypted.length),CKR_OK);
  output_bytes("C_EncryptMessage","sibling-one",&encrypted,cipher,16);
  reset_output(&decoded,16);
  rv("C_DecryptMessage","sibling-one",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,decoded.bytes+1,&decoded.length),CKR_OK);
  output_bytes("C_DecryptMessage","sibling-one",&decoded,plain,16);
  rv("C_MessageEncryptFinal","sibling-release",a->C_MessageEncryptFinal(f.session),CKR_OK);
  reset_output(&decoded,16);
  rv("C_DecryptMessage","sibling-survives",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,decoded.bytes+1,&decoded.length),CKR_OK);
  output_bytes("C_DecryptMessage","sibling-survives",&decoded,plain,16);
  rv("C_MessageDecryptFinal","sibling-release",a->C_MessageDecryptFinal(f.session),CKR_OK);

  /* Both empty data pointer shapes are real HMAC messages. */
  rv("C_SignInit","empty-reference",a->C_SignInit(reference.session,&hmac,reference.mac),CKR_OK);
  reset_output(&classic,32);
  rv("C_Sign","empty-reference",a->C_Sign(reference.session,NULL,0,classic.bytes+1,&classic.length),CKR_OK);
  rv("C_MessageSignInit","empty-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","empty-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  for (unsigned shape=0;shape<2;++shape) {
    CK_BYTE *input=shape ? &presentEmpty : NULL;
    const char *leg=shape ? "empty-present" : "empty-null";
    reset_output(&decoded,32);
    rv("C_SignMessage",leg,a->C_SignMessage(f.session,input,0,input,0,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_SignMessage",leg,&decoded,classic.bytes+1,32);
    rv("C_VerifyMessage",leg,a->C_VerifyMessage(f.session,input,0,input,0,classic.bytes+1,32),CKR_OK);
    rv("C_SignMessageBegin",leg,a->C_SignMessageBegin(f.session,input,0),CKR_OK);
    rv("C_SignMessageNext",leg,a->C_SignMessageNext(f.session,input,0,input,0,NULL,NULL),CKR_OK);
    reset_output(&decoded,32);
    rv("C_SignMessageNext","empty-terminal",a->C_SignMessageNext(f.session,input,0,input,0,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_SignMessageNext",leg,&decoded,classic.bytes+1,32);
    rv("C_VerifyMessageBegin",leg,a->C_VerifyMessageBegin(f.session,input,0),CKR_OK);
    rv("C_VerifyMessageNext",leg,a->C_VerifyMessageNext(f.session,input,0,input,0,NULL,0),CKR_OK);
    rv("C_VerifyMessageNext","empty-terminal",a->C_VerifyMessageNext(f.session,input,0,input,0,classic.bytes+1,32),CKR_OK);
  }
  rv("C_MessageSignFinal","empty-final",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_MessageVerifyFinal","empty-final",a->C_MessageVerifyFinal(f.session),CKR_OK);

  rv("C_MessageEncryptInit","close-open-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_EncryptMessageBegin","close-open-begin",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  close_fixture(a,f);
  f=fixture(a);
  rv("C_MessageEncryptFinal","fresh-session-no-context",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageDecryptFinal","fresh-session-no-context",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageSignFinal","fresh-session-no-context",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyFinal","fresh-session-no-context",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  close_fixture(a,f);
  close_fixture(a,reference);
}

static void oversize_legs(MessageApi *a) {
  directProbe=1;
  Fixture f=fixture(a);
  Output o;
  CK_ULONG limit=16UL*1024UL*1024UL;
  CK_BYTE *large=malloc((size_t)limit);
  if (!large) exit(2);
  memset(large,0x61,(size_t)limit);
  rv("C_MessageSignInit","direct-only-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_SignMessageBegin","direct-only-begin",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_SignMessageNext","direct-only-full-bound",a->C_SignMessageNext(f.session,NULL,0,large,limit,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","direct-only-accumulation-overflow",a->C_SignMessageNext(f.session,NULL,0,textBytes,1,NULL,NULL),CKR_ARGUMENTS_BAD);
  rv("C_SignMessageBegin","direct-only-begin-after-abort",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_SignMessageNext","direct-only-part",a->C_SignMessageNext(f.session,NULL,0,textBytes,3,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","direct-only-session-before-bound",a->C_SignMessageNext(~0UL,NULL,0,textBytes,limit+1,NULL,NULL),CKR_SESSION_HANDLE_INVALID);
  rv("C_SignMessageNext","direct-only-single-input-too-large",a->C_SignMessageNext(f.session,NULL,0,textBytes,limit+1,NULL,NULL),CKR_ARGUMENTS_BAD);
  reset_output(&o,32);
  rv("C_SignMessageNext","direct-only-open-message-preserved",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessageNext","direct-only-normal-hmac",&o,witness,32);
  rv("C_MessageSignFinal","direct-only-final",a->C_MessageSignFinal(f.session),CKR_OK);
  free(large);
  close_fixture(a,f);
  directProbe=0;
}

/* T-M01 flag-to-init sweep: every CKF_MESSAGE_* flag the token
 * advertises must round-trip into a successful message init, and
 * rows the DG1 rule excludes (CCM, ChaCha20-Poly1305, the SSL3
 * MACs) must carry no message flag. The list count is pinned to
 * the HASKOKI_MECH_COUNT value (316), independently enforced by
 * scripts/check-mechanisms.py and the evidence invariants; the
 * literal keeps this consumer on the pinned headers only. */
#define SWEEP_MECH_COUNT 316UL
#define SWEEP_MSG_MASK (CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT|CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY)

static unsigned sweepSwept, sweepAbsent;
static CK_BYTE aes256Bytes[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
static CK_BYTE des3Bytes[24] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23};
static CK_BYTE poly32Bytes[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static CK_BYTE gcmKeyBytes[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
static CK_BYTE gcmNonce[12] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b};
static CK_BYTE gcmAad[8] = {'a','a','d','-','d','a','t','a'};
static CK_BYTE gcmPt[16] = {'H','e','l','l','o',' ','G','C','M',' ','w','o','r','l','d','!'};
static CK_BYTE gcmSealed[32] = {0xdb,0x09,0xcb,0xa2,0x09,0x3b,0xb0,0x17,0x06,0xf2,0x16,0xe5,0x44,0xcf,0x14,0x29,0x39,0xf0,0x38,0x50,0x41,0xaf,0xdf,0xd3,0xa2,0xd5,0xa8,0xe8,0xed,0x69,0xa2,0xe6};

static void sweep_flags(MessageApi *a, CK_MECHANISM_TYPE mech, const char *label, CK_FLAGS want) {
  CK_MECHANISM_INFO info;
  char leg[96];
  CK_RV result=a->C_GetMechanismInfo(tokenSlot,mech,&info);
  snprintf(leg,sizeof(leg),"%s-info",label);
  rv("sweep",leg,result,CKR_OK);
  if (result != CKR_OK) return;
  snprintf(leg,sizeof(leg),"%s-flags",label);
  check("sweep",leg,(info.flags & SWEEP_MSG_MASK) == want);
  printf("sweep:flag/%s/3.%u flags=0x%lx expect=0x%lx\n",label,minor,(unsigned long)(info.flags & SWEEP_MSG_MASK),(unsigned long)want);
}

static void sweep_cipher(MessageApi *a, CK_SESSION_HANDLE session, const char *label, CK_MECHANISM *m, CK_OBJECT_HANDLE encKey, CK_OBJECT_HANDLE decKey) {
  char leg[96];
  snprintf(leg,sizeof(leg),"%s-encrypt-init",label);
  rv("sweep",leg,a->C_MessageEncryptInit(session,m,encKey),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-encrypt-final",label);
  rv("sweep",leg,a->C_MessageEncryptFinal(session),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-decrypt-init",label);
  rv("sweep",leg,a->C_MessageDecryptInit(session,m,decKey),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-decrypt-final",label);
  rv("sweep",leg,a->C_MessageDecryptFinal(session),CKR_OK);
  ++sweepSwept;
}

static void sweep_sign(MessageApi *a, CK_SESSION_HANDLE session, const char *label, CK_MECHANISM *m, CK_OBJECT_HANDLE signKey, CK_OBJECT_HANDLE verifyKey) {
  char leg[96];
  snprintf(leg,sizeof(leg),"%s-sign-init",label);
  rv("sweep",leg,a->C_MessageSignInit(session,m,signKey),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-sign-final",label);
  rv("sweep",leg,a->C_MessageSignFinal(session),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-verify-init",label);
  rv("sweep",leg,a->C_MessageVerifyInit(session,m,verifyKey),CKR_OK);
  snprintf(leg,sizeof(leg),"%s-verify-final",label);
  rv("sweep",leg,a->C_MessageVerifyFinal(session),CKR_OK);
  ++sweepSwept;
}

static void sweep_absent(MessageApi *a, CK_MECHANISM_TYPE mech, const char *label) {
  sweep_flags(a,mech,label,0);
  ++sweepAbsent;
}

static void sweep_keypair(MessageApi *a, CK_SESSION_HANDLE session, const char *leg, CK_MECHANISM_TYPE kgm, CK_ATTRIBUTE *pubT, CK_ULONG pubN, CK_ATTRIBUTE *privT, CK_ULONG privN, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
  CK_MECHANISM m={kgm,NULL,0};
  CK_RV result=a->C_GenerateKeyPair(session,&m,pubT,pubN,privT,privN,pub,priv);
  rv("sweep",leg,result,CKR_OK);
  if (result != CKR_OK) exit(1);
}

static void sweep_gcm_kat(MessageApi *a, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
  /* Per-message GCM parameters ride the gcm-params/1 image
   * (BE64 tag length, BE64 IV length, IV; the AAD travels in the
   * associated-data slot, never embedded). */
  static CK_BYTE gcmMsgParams[28] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b};
  CK_GCM_PARAMS gp={gcmNonce,12,96,NULL,0,128};
  CK_MECHANISM m={CKM_AES_GCM,(CK_VOID_PTR)&gp,sizeof(gp)};
  Output sealed, opened;
  rv("sweep","gcm-kat-encrypt-init",a->C_MessageEncryptInit(session,&m,key),CKR_OK);
  reset_output(&sealed,64);
  rv("sweep","gcm-kat-encrypt",a->C_EncryptMessage(session,gcmMsgParams,sizeof(gcmMsgParams),gcmAad,8,gcmPt,16,sealed.bytes+1,&sealed.length),CKR_OK);
  output_bytes("sweep","gcm-kat-sealed",&sealed,gcmSealed,32);
  rv("sweep","gcm-kat-encrypt-final",a->C_MessageEncryptFinal(session),CKR_OK);
  rv("sweep","gcm-kat-decrypt-init",a->C_MessageDecryptInit(session,&m,key),CKR_OK);
  reset_output(&opened,64);
  rv("sweep","gcm-kat-decrypt",a->C_DecryptMessage(session,gcmMsgParams,sizeof(gcmMsgParams),gcmAad,8,sealed.bytes+1,sealed.length,opened.bytes+1,&opened.length),CKR_OK);
  output_bytes("sweep","gcm-kat-opened",&opened,gcmPt,16);
  rv("sweep","gcm-kat-decrypt-final",a->C_MessageDecryptFinal(session),CKR_OK);
}

static void sweep_ecdsa_msg(MessageApi *a, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub) {
  static CK_BYTE data[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
  static CK_BYTE sig[256];
  CK_ULONG sigLen=sizeof(sig);
  CK_MECHANISM m={CKM_ECDSA_SHA256,NULL,0};
  rv("sweep","ecdsa-msg-sign-init",a->C_MessageSignInit(session,&m,priv),CKR_OK);
  rv("sweep","ecdsa-msg-sign",a->C_SignMessage(session,NULL,0,data,sizeof(data),sig,&sigLen),CKR_OK);
  check("sweep","ecdsa-msg-siglen",sigLen > 0 && sigLen <= sizeof(sig));
  rv("sweep","ecdsa-msg-sign-final",a->C_MessageSignFinal(session),CKR_OK);
  rv("sweep","ecdsa-msg-verify-init",a->C_MessageVerifyInit(session,&m,pub),CKR_OK);
  rv("sweep","ecdsa-msg-verify",a->C_VerifyMessage(session,NULL,0,data,sizeof(data),sig,sigLen),CKR_OK);
  rv("sweep","ecdsa-msg-verify-final",a->C_MessageVerifyFinal(session),CKR_OK);
}

static void sweep_legs(MessageApi *a) {
  CK_ULONG count=0;
  CK_RV result=a->C_GetMechanismList(tokenSlot,NULL,&count);
  rv("sweep","list-count",result,CKR_OK);
  printf("sweep:list count=%lu expected=316\n",(unsigned long)count);
  check("sweep","list-count-316",count == SWEEP_MECH_COUNT);
  {
    CK_MECHANISM_TYPE mechs[512];
    CK_ULONG n=512;
    result=a->C_GetMechanismList(tokenSlot,mechs,&n);
    rv("sweep","list-fetch",result,CKR_OK);
    check("sweep","list-fetch-316",n == SWEEP_MECH_COUNT);
  }
  sweepSwept=0;
  sweepAbsent=0;
  {
    CK_SESSION_HANDLE s=0;
    CK_OBJECT_HANDLE aes, des3, hmac20, poly, gcmk, xts;
    CK_OBJECT_HANDLE rsaPub, rsaPriv, ecPub, ecPriv, edPub, edPriv, mlPub, mlPriv, slhPub, slhPriv;
    CK_OBJECT_CLASS pcls=CKO_PUBLIC_KEY, scls=CKO_PRIVATE_KEY;
    CK_KEY_TYPE rkt=CKK_RSA, ekt=CKK_EC, edkt=CKK_EC_EDWARDS;
    CK_KEY_TYPE mkt=CKK_ML_DSA, skt=CKK_SLH_DSA;
    CK_BBOOL bFalse=CK_FALSE, bTrue=CK_TRUE;
    CK_ULONG bits2048=2048;
    static const CK_BYTE p256oid[]={0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
    static CK_BYTE edParams[]={0x06,0x03,0x2B,0x65,0x70};
    CK_ULONG mset65=CKP_ML_DSA_65, sset1=CKP_SLH_DSA_SHA2_128S;
    CK_BYTE iv8[8]={0,1,2,3,4,5,6,7};
    CK_AES_CTR_PARAMS ctr={128,{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}};
    CK_GCM_PARAMS gcm={gcmNonce,12,96,NULL,0,128};
    CK_ULONG genLen=16;
    CK_RSA_PKCS_PSS_PARAMS pss={CKM_SHA256,CKG_MGF1_SHA256,20};
    CK_RSA_PKCS_OAEP_PARAMS oaep={CKM_SHA_1,CKG_MGF1_SHA1,CKZ_DATA_SPECIFIED,NULL,0};
    CK_MECHANISM mAesCbc={CKM_AES_CBC,iv,16}, mAesCbcPad={CKM_AES_CBC_PAD,iv,16};
    CK_MECHANISM mAesEcb={CKM_AES_ECB,NULL,0}, mAesCtr={CKM_AES_CTR,(CK_VOID_PTR)&ctr,sizeof(ctr)};
    CK_MECHANISM mAesGcm={CKM_AES_GCM,(CK_VOID_PTR)&gcm,sizeof(gcm)};
    CK_MECHANISM mAesXts={CKM_AES_XTS,iv,16}, mAesKw={CKM_AES_KEY_WRAP,NULL,0};
    CK_MECHANISM mDes3Cbc={CKM_DES3_CBC,iv8,8};
    CK_MECHANISM mHmac={CKM_SHA256_HMAC,NULL,0};
    CK_MECHANISM mHmacGen={CKM_SHA256_HMAC_GENERAL,(CK_VOID_PTR)&genLen,sizeof(genLen)};
    CK_MECHANISM mCmac={CKM_AES_CMAC,NULL,0}, mGmac={CKM_AES_GMAC,(CK_VOID_PTR)&gcm,sizeof(gcm)};
    CK_MECHANISM mXcbc={CKM_AES_XCBC_MAC,NULL,0}, mDes3Mac={CKM_DES3_MAC,NULL,0};
    CK_MECHANISM mPoly={CKM_POLY1305,NULL,0};
    CK_MECHANISM mRsaPkcs={CKM_SHA256_RSA_PKCS,NULL,0}, mX509={CKM_RSA_X_509,NULL,0};
    CK_MECHANISM mX931={CKM_RSA_X9_31,NULL,0};
    CK_MECHANISM mPss={CKM_SHA256_RSA_PKCS_PSS,(CK_VOID_PTR)&pss,sizeof(pss)};
    CK_MECHANISM mOaep={CKM_RSA_PKCS_OAEP,(CK_VOID_PTR)&oaep,sizeof(oaep)};
    CK_MECHANISM mEcdsa={CKM_ECDSA_SHA256,NULL,0}, mEd={CKM_EDDSA,NULL,0};
    CK_MECHANISM mMl={CKM_ML_DSA,NULL,0}, mSlh={CKM_SLH_DSA,NULL,0};
    CK_ATTRIBUTE rsaPubT[]={
      {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&rkt,sizeof(rkt)},
      {CKA_MODULUS_BITS,&bits2048,sizeof(bits2048)},{CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_ENCRYPT,&bTrue,sizeof(bTrue)},{CKA_VERIFY,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE rsaPrivT[]={
      {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&rkt,sizeof(rkt)},
      {CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_DECRYPT,&bTrue,sizeof(bTrue)},{CKA_SIGN,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE ecPubT[]={
      {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&ekt,sizeof(ekt)},
      {CKA_EC_PARAMS,(CK_VOID_PTR)p256oid,sizeof(p256oid)},{CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_VERIFY,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE ecPrivT[]={
      {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&ekt,sizeof(ekt)},
      {CKA_TOKEN,&bFalse,sizeof(bFalse)},{CKA_SIGN,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE edPubT[]={
      {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&edkt,sizeof(edkt)},
      {CKA_EC_PARAMS,edParams,sizeof(edParams)},{CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_VERIFY,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE edPrivT[]={
      {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&edkt,sizeof(edkt)},
      {CKA_TOKEN,&bFalse,sizeof(bFalse)},{CKA_SIGN,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE mlPubT[]={
      {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&mkt,sizeof(mkt)},
      {CKA_PARAMETER_SET,&mset65,sizeof(mset65)},{CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_VERIFY,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE mlPrivT[]={
      {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&mkt,sizeof(mkt)},
      {CKA_TOKEN,&bFalse,sizeof(bFalse)},{CKA_SIGN,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE slhPubT[]={
      {CKA_CLASS,&pcls,sizeof(pcls)},{CKA_KEY_TYPE,&skt,sizeof(skt)},
      {CKA_PARAMETER_SET,&sset1,sizeof(sset1)},{CKA_TOKEN,&bFalse,sizeof(bFalse)},
      {CKA_VERIFY,&bTrue,sizeof(bTrue)}};
    CK_ATTRIBUTE slhPrivT[]={
      {CKA_CLASS,&scls,sizeof(scls)},{CKA_KEY_TYPE,&skt,sizeof(skt)},
      {CKA_TOKEN,&bFalse,sizeof(bFalse)},{CKA_SIGN,&bTrue,sizeof(bTrue)}};
    result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&s);
    rv("sweep","open",result,CKR_OK);
    if (result != CKR_OK) exit(1);
    aes=make_key(a,s,CKK_AES,aes256Bytes,32,CK_TRUE,CK_TRUE,CK_TRUE,CK_TRUE);
    des3=make_key(a,s,CKK_DES3,des3Bytes,24,CK_TRUE,CK_TRUE,CK_TRUE,CK_TRUE);
    hmac20=make_key(a,s,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_TRUE);
    poly=make_key(a,s,CKK_POLY1305,poly32Bytes,32,CK_FALSE,CK_FALSE,CK_TRUE,CK_TRUE);
    gcmk=make_key(a,s,CKK_AES,gcmKeyBytes,16,CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);
    xts=make_key(a,s,CKK_AES_XTS,aes256Bytes,32,CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);
    sweep_keypair(a,s,"rsa-pair",CKM_RSA_PKCS_KEY_PAIR_GEN,rsaPubT,6,rsaPrivT,5,&rsaPub,&rsaPriv);
    sweep_keypair(a,s,"ec-pair",CKM_EC_KEY_PAIR_GEN,ecPubT,5,ecPrivT,4,&ecPub,&ecPriv);
    sweep_keypair(a,s,"ed-pair",CKM_EC_EDWARDS_KEY_PAIR_GEN,edPubT,5,edPrivT,4,&edPub,&edPriv);
    sweep_keypair(a,s,"mldsa-pair",CKM_ML_DSA_KEY_PAIR_GEN,mlPubT,5,mlPrivT,4,&mlPub,&mlPriv);
    sweep_keypair(a,s,"slhdsa-pair",CKM_SLH_DSA_KEY_PAIR_GEN,slhPubT,5,slhPrivT,4,&slhPub,&slhPriv);
    sweep_flags(a,CKM_AES_CBC,"aes-cbc",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-cbc",&mAesCbc,aes,aes);
    sweep_flags(a,CKM_AES_CBC_PAD,"aes-cbc-pad",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-cbc-pad",&mAesCbcPad,aes,aes);
    sweep_flags(a,CKM_AES_ECB,"aes-ecb",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-ecb",&mAesEcb,aes,aes);
    sweep_flags(a,CKM_AES_CTR,"aes-ctr",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-ctr",&mAesCtr,aes,aes);
    sweep_flags(a,CKM_AES_GCM,"aes-gcm",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-gcm",&mAesGcm,aes,aes);
    sweep_flags(a,CKM_AES_XTS,"aes-xts",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-xts",&mAesXts,xts,xts);
    sweep_flags(a,CKM_AES_KEY_WRAP,"aes-kw",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"aes-kw",&mAesKw,aes,aes);
    sweep_flags(a,CKM_DES3_CBC,"des3-cbc",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"des3-cbc",&mDes3Cbc,des3,des3);
    sweep_flags(a,CKM_SHA256_HMAC,"hmac-sha256",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"hmac-sha256",&mHmac,hmac20,hmac20);
    sweep_flags(a,CKM_SHA256_HMAC_GENERAL,"hmac-sha256-general",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"hmac-sha256-general",&mHmacGen,hmac20,hmac20);
    sweep_flags(a,CKM_AES_CMAC,"aes-cmac",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"aes-cmac",&mCmac,aes,aes);
    sweep_flags(a,CKM_AES_GMAC,"aes-gmac",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"aes-gmac",&mGmac,aes,aes);
    sweep_flags(a,CKM_AES_XCBC_MAC,"aes-xcbc-mac",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"aes-xcbc-mac",&mXcbc,aes,aes);
    sweep_flags(a,CKM_DES3_MAC,"des3-mac",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"des3-mac",&mDes3Mac,des3,des3);
    sweep_flags(a,CKM_POLY1305,"poly1305",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"poly1305",&mPoly,poly,poly);
    sweep_flags(a,CKM_SHA256_RSA_PKCS,"rsa-pkcs",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"rsa-pkcs",&mRsaPkcs,rsaPriv,rsaPub);
    sweep_flags(a,CKM_RSA_X_509,"rsa-x509",SWEEP_MSG_MASK);
    sweep_sign(a,s,"rsa-x509",&mX509,rsaPriv,rsaPub);
    sweep_cipher(a,s,"rsa-x509",&mX509,rsaPub,rsaPriv);
    sweep_flags(a,CKM_RSA_X9_31,"rsa-x931",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"rsa-x931",&mX931,rsaPriv,rsaPub);
    sweep_flags(a,CKM_SHA256_RSA_PKCS_PSS,"rsa-pss",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"rsa-pss",&mPss,rsaPriv,rsaPub);
    sweep_flags(a,CKM_RSA_PKCS_OAEP,"rsa-oaep",CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT);
    sweep_cipher(a,s,"rsa-oaep",&mOaep,rsaPub,rsaPriv);
    sweep_flags(a,CKM_ECDSA_SHA256,"ecdsa-sha256",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"ecdsa-sha256",&mEcdsa,ecPriv,ecPub);
    sweep_flags(a,CKM_EDDSA,"eddsa",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"eddsa",&mEd,edPriv,edPub);
    sweep_flags(a,CKM_ML_DSA,"ml-dsa",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"ml-dsa",&mMl,mlPriv,mlPub);
    sweep_flags(a,CKM_SLH_DSA,"slh-dsa",CKF_MESSAGE_SIGN|CKF_MESSAGE_VERIFY);
    sweep_sign(a,s,"slh-dsa",&mSlh,slhPriv,slhPub);
    sweep_absent(a,CKM_AES_CCM,"aes-ccm");
    sweep_absent(a,CKM_CHACHA20_POLY1305,"chacha20-poly1305");
    sweep_absent(a,CKM_SSL3_MD5_MAC,"ssl3-md5-mac");
    sweep_absent(a,CKM_SSL3_SHA1_MAC,"ssl3-sha1-mac");
    sweep_gcm_kat(a,s,gcmk);
    sweep_ecdsa_msg(a,s,ecPriv,ecPub);
    printf("sweep:summary swept=%u absent=%u\n",sweepSwept,sweepAbsent);
    rv("sweep","close",a->C_CloseSession(s),CKR_OK);
  }
}
