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

/* CFB64 kept-refusal proof: CKM_AES_CFB64 (0x00002105) stays
 * unadvertised and refused on every versioned table. List legs pin
 * its absence from C_GetMechanismList; info legs pin the
 * CKR_MECHANISM_INVALID refusal from C_GetMechanismInfo; init legs
 * pin the CKR_MECHANISM_INVALID refusal from C_EncryptInit and
 * C_DecryptInit with a plausible 16-byte IV, plus a follow-up
 * C_EncryptInit on CKM_AES_CBC proving no state change.
 *
 * Usage: cfb64_kept <module> [--version 2.40|3.0|3.1|3.2]
 *                           [--legs kept|all]
 * Exit 0 iff every selected leg passes; 1 on any leg failure; 2 on
 * setup failure (usage, config, load, discovery).
 */
static int failures;
static char ver[8];
static CK_SLOT_ID tokenSlot;
static char configPath[256];
static CK_BYTE aesBytes[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static CK_BYTE ivBytes[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f};

typedef struct {
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CreateObject C_CreateObject;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_DecryptInit C_DecryptInit;
} KeptApi;
typedef struct { CK_SESSION_HANDLE session; CK_OBJECT_HANDLE aes; } Fixture;

static void check(const char *entry, const char *leg, int good) {
  printf("cfb64:%s/%s/%s check=%s\n",entry,leg,ver,good ? "ok" : "FAIL");
  if (!good) ++failures;
}
static void rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  printf("cfb64:%s/%s/%s rv=0x%lx expected=0x%lx\n",entry,leg,ver,(unsigned long)got,(unsigned long)want);
  if (got != want) ++failures;
}

static void configure(void) {
  char path[]="/tmp/haskoki-cfb64-config-XXXXXX";
  const char body[]="schema_version = 1\nprofile = \"real-crypto\"\n[storage]\nkind = \"memory\"\n[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\nprivate_library_context = true\n[trace]\nenabled = false\n";
  int fd=mkstemp(path);
  if (fd<0 || write(fd,body,sizeof(body)-1)!=(ssize_t)(sizeof(body)-1)) exit(2);
  close(fd);
  snprintf(configPath,sizeof(configPath),"%s",path);
  if (setenv("HASKOKI_CONFIG",configPath,1)!=0) exit(2);
}

static KeptApi read_legacy(CK_FUNCTION_LIST *table) {
  KeptApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_DecryptInit=table->C_DecryptInit;
  check("C_GetMechanismInfo","slot-present",a.C_GetMechanismInfo != NULL);
  check("C_EncryptInit","slot-present",a.C_EncryptInit != NULL);
  check("C_DecryptInit","slot-present",a.C_DecryptInit != NULL);
  return a;
}
static KeptApi read_common(CK_FUNCTION_LIST_3_0 *table) {
  KeptApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_DecryptInit=table->C_DecryptInit;
  check("C_GetMechanismInfo","slot-present",a.C_GetMechanismInfo != NULL);
  check("C_EncryptInit","slot-present",a.C_EncryptInit != NULL);
  check("C_DecryptInit","slot-present",a.C_DecryptInit != NULL);
  return a;
}
static KeptApi read_newest(CK_FUNCTION_LIST_3_2 *table) {
  KeptApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_GetMechanismList=table->C_GetMechanismList;
  a.C_GetMechanismInfo=table->C_GetMechanismInfo;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_DecryptInit=table->C_DecryptInit;
  check("C_GetMechanismInfo","slot-present",a.C_GetMechanismInfo != NULL);
  check("C_EncryptInit","slot-present",a.C_EncryptInit != NULL);
  check("C_DecryptInit","slot-present",a.C_DecryptInit != NULL);
  return a;
}

/* One session plus one AES-256 usage key per fixture (encrypt and
 * decrypt permitted, so the legs prove mechanism refusal rather
 * than a key-permission refusal). */
static Fixture fixture(KeptApi *a) {
  Fixture f={0,0};
  CK_OBJECT_CLASS cls=CKO_SECRET_KEY;
  CK_KEY_TYPE type=CKK_AES;
  CK_BBOOL no=CK_FALSE, yes=CK_TRUE;
  CK_ATTRIBUTE attrs[]={
    {CKA_CLASS,&cls,sizeof(cls)},{CKA_KEY_TYPE,&type,sizeof(type)},
    {CKA_TOKEN,&no,sizeof(no)},{CKA_VALUE,aesBytes,sizeof(aesBytes)},
    {CKA_ENCRYPT,&yes,sizeof(yes)},{CKA_DECRYPT,&yes,sizeof(yes)}
  };
  CK_RV result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&f.session);
  rv("setup","fixture-open",result,CKR_OK);
  if (result != CKR_OK || f.session==0) exit(2);
  result=a->C_CreateObject(f.session,attrs,6,&f.aes);
  rv("setup","fixture-key",result,CKR_OK);
  if (result != CKR_OK || f.aes==0) exit(2);
  return f;
}
static void close_fixture(KeptApi *a, Fixture f) {
  rv("setup","fixture-close",a->C_CloseSession(f.session),CKR_OK);
}

static void kept_list(KeptApi *a) {
  CK_MECHANISM_TYPE listed[512];
  CK_ULONG count=0, i;
  int good=1, found=0;
  CK_RV result=a->C_GetMechanismList(tokenSlot,NULL,&count);
  rv("setup","list-query",result,CKR_OK); good &= result==CKR_OK;
  good &= count>0 && count<=512;
  result=a->C_GetMechanismList(tokenSlot,listed,&count);
  rv("setup","list-fill",result,CKR_OK); good &= result==CKR_OK;
  for (i=0;i<count;++i) if (listed[i]==CKM_AES_CFB64) found=1;
  printf("cfb64:kept/list-count/%s count=%lu found=%d\n",ver,(unsigned long)count,found);
  good &= !found;
  check("kept","list",good);
}
static void kept_info(KeptApi *a) {
  CK_MECHANISM_INFO info;
  int good=1;
  CK_RV result;
  memset(&info,0,sizeof(info));
  result=a->C_GetMechanismInfo(tokenSlot,CKM_AES_CFB64,&info);
  rv("kept","info",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  check("kept","info",good);
}
static void kept_init(KeptApi *a) {
  Fixture f=fixture(a);
  CK_MECHANISM m={CKM_AES_CFB64,ivBytes,sizeof(ivBytes)};
  CK_MECHANISM ok={CKM_AES_CBC,ivBytes,sizeof(ivBytes)};
  int good=1;
  CK_RV result;
  result=a->C_EncryptInit(f.session,&m,f.aes);
  rv("kept","init-encrypt",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_DecryptInit(f.session,&m,f.aes);
  rv("kept","init-decrypt",result,CKR_MECHANISM_INVALID); good &= result==CKR_MECHANISM_INVALID;
  result=a->C_EncryptInit(f.session,&ok,f.aes);
  rv("kept","init-followup",result,CKR_OK); good &= result==CKR_OK;
  check("kept","init",good);
  close_fixture(a,f);
}

static int want_leg(const char *which, const char *name) {
  return strcmp(which,"all")==0 || strcmp(which,name)==0;
}
static int want_ver(const char *only, const char *v) {
  return only==NULL || strcmp(only,v)==0;
}
static void run_legs(KeptApi *a, const char *which) {
  if (want_leg(which,"kept")) {
    kept_list(a);
    kept_info(a);
    kept_init(a);
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
  if (!(strcmp(which,"all")==0 || strcmp(which,"kept")==0)) return 2;
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
    KeptApi a;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    CK_RV result;
    snprintf(ver,sizeof(ver),"%s","2.40");
    result=getList(&list);
    rv("C_GetFunctionList","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !list) return 1;
    check("C_GetFunctionList","version",list->version.major==2 && list->version.minor==40);
    a=read_legacy(list);
    if (!a.C_GetMechanismInfo || !a.C_EncryptInit || !a.C_DecryptInit) return 1;
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
    KeptApi a;
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
    if (!a.C_GetMechanismInfo || !a.C_EncryptInit || !a.C_DecryptInit) return 1;
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
  printf("cfb64:summary legs=%s failed=%d\n",which,failures);
  if (failures) return 1;
  printf("PASS: cfb64_kept (%s)\n",which);
  return 0;
}
