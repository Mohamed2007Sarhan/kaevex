#include "../src/engines/link_core.h"
static int fails=0,total=0;
#define CHECK(c,m) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",m,__LINE__);} }while(0)
int main(void){
  char code[160]; LinkCode lc;
  CHECK(link_build_code("192.168.1.20",9009,"123456",code,sizeof code) && strcmp(code,"KAEVEX-LINK-V2://192.168.1.20:9009/123456")==0,"build");
  CHECK(link_parse_code(code,&lc) && strcmp(lc.host,"192.168.1.20")==0 && lc.port==9009 && strcmp(lc.pin,"123456")==0,"roundtrip");
  CHECK(link_parse_code("  \"KAEVEX-LINK-V2://PC-01.lan:9009/000001\"\r\n",&lc) && strcmp(lc.host,"PC-01.lan")==0,"paste noise + hostname");
  CHECK(!link_parse_code("KAEVEX-CLUSTER-V1://abc:host:1:ECDH",&lc),"old fake format rejected");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://1.2.3.4:0/123456",&lc),"port 0");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://1.2.3.4:99999/123456",&lc),"port big");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://1.2.3.4:9009/12345",&lc),"short pin");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://1.2.3.4:9009/12345a",&lc),"alpha pin");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://a b:9009/123456",&lc),"space in host");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://x/y:9009/123456",&lc) ,"slash in host");
  CHECK(!link_parse_code("KAEVEX-LINK-V2://1.2.3.4/123456",&lc),"missing port");
  CHECK(!link_build_code("bad host",9009,"123456",code,sizeof code),"build rejects bad host");
  char tiny[10]; CHECK(!link_build_code("1.2.3.4",9009,"123456",tiny,sizeof tiny),"build small buffer");
  char raw[]="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"online\"}"; int st; char *body;
  CHECK(link_parse_http(raw,&st,&body)&&st==200&&strcmp(body,"{\"status\":\"online\"}")==0,"http parse");
  char r2[]="HTTP/1.1 401 Unauthorized\r\n\r\n{\"error\":\"x\"}"; CHECK(link_parse_http(r2,&st,&body)&&st==401,"401");
  char r3[]="garbage"; CHECK(!link_parse_http(r3,&st,&body),"garbage");
  CHECK(link_is_private_ip("192.168.0.5")&&link_is_private_ip("10.1.2.3")&&link_is_private_ip("172.16.0.1")&&link_is_private_ip("172.31.255.1")&&link_is_private_ip("127.0.0.1")&&link_is_private_ip("100.100.1.1"),"private ok");
  CHECK(!link_is_private_ip("8.8.8.8")&&!link_is_private_ip("172.32.0.1")&&!link_is_private_ip("100.128.0.1")&&!link_is_private_ip("203.0.113.9")&&!link_is_private_ip("1.2.3.4x")&&!link_is_private_ip("999.1.1.1"),"public/invalid rejected");
  printf("%d/%d passed\n",total-fails,total); return fails?1:0; }
