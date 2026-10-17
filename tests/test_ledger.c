#include "../src/engines/ledger_core.h"
static int fails=0,total=0;
#define CHECK(c,m) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",m,__LINE__);} }while(0)
static void hx(const uint8_t*b,size_t n,char*o){ledger_hex(b,n,o);}
int main(void){
  uint8_t d[32]; char h[65];
  sha256_buf("",0,d); hx(d,32,h); CHECK(!strcmp(h,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),"sha256 empty");
  sha256_buf("abc",3,d); hx(d,32,h); CHECK(!strcmp(h,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),"sha256 abc");
  const char *m="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; sha256_buf(m,strlen(m),d); hx(d,32,h); CHECK(!strcmp(h,"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),"sha256 448-bit");
  char *mil=malloc(1000000); memset(mil,'a',1000000); sha256_buf(mil,1000000,d); hx(d,32,h); CHECK(!strcmp(h,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),"sha256 1M a"); free(mil);
  /* RFC 4231 test case 1 and 2 and 6 (long key) */
  uint8_t k1[20]; memset(k1,0x0b,20); hmac_sha256(k1,20,"Hi There",8,NULL,0,d); hx(d,32,h); CHECK(!strcmp(h,"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),"hmac rfc4231 #1");
  hmac_sha256((const uint8_t*)"Jefe",4,"what do ya want ",16,"for nothing?",12,d); hx(d,32,h); CHECK(!strcmp(h,"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),"hmac rfc4231 #2 (split message)");
  uint8_t k6[131]; memset(k6,0xaa,131); const char*t6="Test Using Larger Than Block-Size Key - Hash Key First"; hmac_sha256(k6,131,t6,strlen(t6),NULL,0,d); hx(d,32,h); CHECK(!strcmp(h,"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),"hmac rfc4231 #6 long key");

  /* build a real chain over a log, then tamper */
  uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+3);
  const char *lines[]={"=== Kaevex Forensics Log - Session started 2026-10-05 ===","[2026-10-05 10:00:00] [INFO] AV  scan started","[2026-10-05 10:00:05] [CRITICAL] NET  beacon blocked","[2026-10-05 10:01:00] [INFO] FW  rule added"};
  char log[2000]="", chain[2000]=""; uint8_t prev[32]={0};
  for(int i=0;i<4;i++){ strcat(log,lines[i]); strcat(log,"\n"); if(i==0) continue; uint8_t mac[32]; ledger_mac(key,prev,lines[i],strlen(lines[i]),mac); memcpy(prev,mac,32); char hx2[65]; ledger_hex(mac,32,hx2); char ln[100]; sprintf(ln,"%d %s\n",i,hx2); strcat(chain,ln); }
  LedgerVerdict v; ledger_verify(key,log,chain,&v); CHECK(v.state==LEDGER_OK&&v.sealed==3,"intact chain verifies"); printf("  %s\n",v.why);
  char bad[2000]; strcpy(bad,log); char*q=strstr(bad,"beacon blocked"); memcpy(q,"beacon allowed",14); ledger_verify(key,bad,chain,&v); CHECK(v.state==LEDGER_BROKEN&&v.badLine==2,"edited line detected"); printf("  %s\n",v.why);
  strcpy(bad,"=== Kaevex Forensics Log - Session started 2026-10-05 ===\n[2026-10-05 10:00:00] [INFO] AV  scan started\n[2026-10-05 10:01:00] [INFO] FW  rule added\n"); ledger_verify(key,bad,chain,&v); CHECK(v.state==LEDGER_BROKEN,"deleted line detected"); printf("  %s\n",v.why);
  strcpy(bad,log); strcat(bad,"[2026-10-05 10:02:00] [INFO] injected\n"); ledger_verify(key,bad,chain,&v); CHECK(v.state==LEDGER_TAIL&&v.unsealedTail==1,"unsealed tail flagged"); printf("  %s\n",v.why);
  strcpy(bad,"=== Kaevex Forensics Log - Session started 2026-10-05 ===\n[2026-10-05 10:00:00] [INFO] AV  scan started\n[evil injected line]\n[2026-10-05 10:00:05] [CRITICAL] NET  beacon blocked\n[2026-10-05 10:01:00] [INFO] FW  rule added\n"); ledger_verify(key,bad,chain,&v); CHECK(v.state==LEDGER_BROKEN,"inserted line detected"); printf("  %s\n",v.why);
  uint8_t wrong[32]; memset(wrong,1,32); ledger_verify(wrong,log,chain,&v); CHECK(v.state==LEDGER_BROKEN,"wrong key fails");
  ledger_verify(key,log,"",&v); CHECK(v.state==LEDGER_NOCHAIN,"no chain");
  ledger_verify(key,log,"garbage\n",&v); CHECK(v.state==LEDGER_BROKEN,"corrupt chain");
  char shortLog[300]="=== Kaevex Forensics Log - Session started 2026-10-05 ===\n"; ledger_verify(key,shortLog,chain,&v); CHECK(v.state==LEDGER_BROKEN&&strstr(v.why,"shorter"),"truncation detected");
  printf("%d/%d passed\n",total-fails,total); return fails?1:0; }
