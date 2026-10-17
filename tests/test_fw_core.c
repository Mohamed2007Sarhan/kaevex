#include "../src/engines/fw_pro_core.h"
static int fails=0,total=0;
#define CHECK(c,msg) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",msg,__LINE__);} }while(0)
static FwpRule mk(const char*name,int act,int dir,int proto,const char*prog,const char*rp,const char*ra,int prio){
  FwpRule r; memset(&r,0,sizeof r); snprintf(r.name,sizeof r.name,"%s",name); r.action=act; r.dir=dir; r.proto=proto;
  snprintf(r.program,sizeof r.program,"%s",prog); snprintf(r.remotePorts,sizeof r.remotePorts,"%s",rp);
  snprintf(r.remoteAddrs,sizeof r.remoteAddrs,"%s",ra); r.priority=prio; r.enabled=1; return r; }
int main(void){
  char b[1024];
  /* validation */
  CHECK(fwp_valid_ports("80,443,1000-2000"),"ports ok"); CHECK(!fwp_valid_ports("0"),"port 0"); CHECK(!fwp_valid_ports("70000"),"port big");
  CHECK(!fwp_valid_ports("80;calc"),"port inject"); CHECK(!fwp_valid_ports("2000-1000"),"port rev"); CHECK(!fwp_valid_ports("80,"),"trailing comma");
  CHECK(fwp_valid_addrs("10.0.0.0/8,192.168.1.5,1.1.1.1-1.1.1.9,LocalSubnet"),"addrs ok");
  CHECK(!fwp_valid_addrs("10.0.0.0/33"),"cidr 33"); CHECK(!fwp_valid_addrs("300.1.1.1"),"octet"); CHECK(!fwp_valid_addrs("1.1.1.1\" & calc"),"addr inject");
  CHECK(fwp_valid_addrs("2001:db8::1"),"v6"); CHECK(fwp_valid_addrs("::1"),"v6 loopback"); CHECK(fwp_valid_addrs("fe80::/10"),"v6 cidr");
  CHECK(fwp_valid_addrs("2001:db8:85a3:0:0:8a2e:370:7334"),"v6 full"); CHECK(!fwp_valid_addrs("2001:::1"),"v6 triple"); CHECK(!fwp_valid_addrs("12345::1"),"v6 group len");
  CHECK(!fwp_valid_addrs("1:2:3:4:5:6:7"),"v6 short"); CHECK(!fwp_valid_addrs("::g"),"v6 nonhex");
  CHECK(fwp_valid_program("C:\\Program Files\\App\\a.exe"),"prog ok"); CHECK(!fwp_valid_program("a.exe"),"prog relative");
  CHECK(!fwp_valid_program("C:\\x\\..\\y.exe"),"prog dotdot"); CHECK(!fwp_valid_program("C:\\a\" & calc & \".exe"),"prog quote"); CHECK(!fwp_valid_program("C:\\a.bat"),"prog ext");
  CHECK(fwp_safe_name("Block Telnet-1") && !fwp_safe_name("a\"b") && !fwp_safe_name("a&b") && !fwp_safe_name(""),"names");

  /* netsh build */
  FwpRule r=mk("Block Telnet",FWP_BLOCK,FWP_IN,FWP_TCP,"","23","",5); snprintf(r.localPorts,64,"23"); r.remotePorts[0]=0;
  CHECK(fwp_build_add(&r,FWP_IN,NULL,b,sizeof b),"build"); printf("  %s\n",b);
  CHECK(strstr(b,"name=\"Kaevex-FW-Block Telnet-In\"") && strstr(b,"dir=in action=block") && strstr(b,"localport=23"),"build content");
  FwpRule bad=mk("x",FWP_BLOCK,FWP_OUT,FWP_ANY,"","80","",5); CHECK(!fwp_build_add(&bad,FWP_OUT,NULL,b,sizeof b),"ports w/o proto rejected");
  FwpRule inj=mk("ok",FWP_BLOCK,FWP_OUT,FWP_TCP,"C:\\a.exe\" dir=in","","",5); CHECK(!fwp_build_add(&inj,FWP_OUT,NULL,b,sizeof b),"injection rejected");
  char tiny[40]; FwpRule okr=mk("ok",FWP_ALLOW,FWP_OUT,FWP_TCP,"","443","",5); CHECK(!fwp_build_add(&okr,FWP_OUT,NULL,tiny,sizeof tiny),"small buffer safe");
  FwpRule ic=mk("ping",FWP_BLOCK,FWP_IN,FWP_ICMP4,"","","",5); CHECK(fwp_build_add(&ic,FWP_IN,NULL,b,sizeof b) && strstr(b,"protocol=icmpv4:any,any"),"icmp");
  FwpRule dm=mk("dom",FWP_BLOCK,FWP_OUT,FWP_ANY,"","","",5); CHECK(fwp_build_add(&dm,FWP_OUT,"1.2.3.4,5.6.7.8",b,sizeof b)&&strstr(b,"remoteip=1.2.3.4,5.6.7.8"),"domain ips override");
  r.ifaceMask=FWP_IF_LAN|FWP_IF_WIFI; r.profileMask=FWP_PROF_PRIVATE|FWP_PROF_PUBLIC; fwp_build_add(&r,FWP_IN,NULL,b,sizeof b);
  CHECK(strstr(b,"interfacetype=lan,wireless")&&strstr(b,"profile=private,public"),"iface/profile");

  /* complements */
  fwp_ports_complement("80,443",b,sizeof b); CHECK(strcmp(b,"1-79,81-442,444-65535")==0,"ports complement"); printf("  ports: %s\n",b);
  fwp_ports_complement("1-65535",b,sizeof b); CHECK(b[0]==0,"all ports allowed => nothing to block");
  fwp_ports_complement("",b,sizeof b); CHECK(strcmp(b,"1-65535")==0,"empty => block all");
  fwp_ports_complement("443,80,81,82,443",b,sizeof b); CHECK(strcmp(b,"1-79,83-442,444-65535")==0,"merge+sort");
  fwp_ports_complement("1,65535",b,sizeof b); CHECK(strcmp(b,"2-65534")==0,"edges");
  fwp_ipv4_complement("8.8.8.8",b,sizeof b); CHECK(strcmp(b,"0.0.0.0-8.8.8.7,8.8.8.9-255.255.255.255")==0,"ip complement"); printf("  ip: %s\n",b);
  fwp_ipv4_complement("0.0.0.0-255.255.255.255",b,sizeof b); CHECK(b[0]==0,"full range");
  fwp_ipv4_complement("10.0.0.0/8",b,sizeof b); CHECK(strcmp(b,"0.0.0.0-9.255.255.255,11.0.0.0-255.255.255.255")==0,"cidr complement");
  fwp_ipv4_complement("1.1.1.1,1.1.1.2",b,sizeof b); CHECK(strcmp(b,"0.0.0.0-1.1.1.0,1.1.1.3-255.255.255.255")==0,"adjacent merge");

  /* sandbox: Game.exe -> internet only to 443, no LAN */
  FwpSandbox sb; memset(&sb,0,sizeof sb); snprintf(sb.program,260,"C:\\Games\\Game.exe"); sb.allowInternet=1; sb.allowLan=0; snprintf(sb.allowPorts,64,"443");
  FwpRule out[8]; int n=fwp_sandbox_compile(&sb,"Game",out,8); CHECK(n==3,"sandbox rules count");
  FwpConn c={0}; snprintf(c.program,260,"C:\\Games\\Game.exe"); c.dir=FWP_OUT; c.proto=FWP_TCP;
  snprintf(c.remoteIp,48,"192.168.1.20"); c.remotePort=443; CHECK(fwp_eval(out,n,&c,NULL,NULL)==FWP_BLOCK,"sandbox blocks LAN even on 443");
  snprintf(c.remoteIp,48,"203.0.113.5"); c.remotePort=443; CHECK(fwp_eval(out,n,&c,NULL,NULL)==FWP_ALLOW,"sandbox allows internet:443");
  c.remotePort=22; CHECK(fwp_eval(out,n,&c,NULL,NULL)==FWP_BLOCK,"sandbox blocks custom port");
  for(int i=0;i<n;i++){ CHECK(fwp_build_add(&out[i],out[i].dir==FWP_IN?FWP_IN:FWP_OUT,NULL,b,sizeof b),"sandbox rule valid for netsh"); }

  /* priority + schedule */
  FwpRule pol[3]; pol[0]=mk("allow chrome",FWP_ALLOW,FWP_OUT,FWP_TCP,"C:\\c.exe","443","",1); pol[1]=mk("block all out",FWP_BLOCK,FWP_OUT,FWP_ANY,"","","",50);
  FwpConn cc={0}; cc.dir=FWP_OUT; cc.proto=FWP_TCP; cc.remotePort=443; snprintf(cc.remoteIp,48,"1.1.1.1"); snprintf(cc.program,260,"C:\\c.exe");
  int m; CHECK(fwp_eval(pol,2,&cc,NULL,&m)==FWP_ALLOW && m==0,"higher priority allow wins"); snprintf(cc.program,260,"C:\\other.exe");
  CHECK(fwp_eval(pol,2,&cc,NULL,&m)==FWP_BLOCK && m==1,"others blocked");
  cc.dir=FWP_IN; CHECK(fwp_eval(pol,0,&cc,NULL,&m)==FWP_BLOCK && m==-1,"default inbound block");
  cc.dir=FWP_OUT; CHECK(fwp_eval(pol,0,&cc,NULL,&m)==FWP_ALLOW,"default outbound allow");
  int pairs[4][2]; CHECK(fwp_find_conflicts(pol,2,pairs,4)==1,"detects priority/Windows-block conflict");
  FwpRule sc=mk("night",FWP_BLOCK,FWP_OUT,FWP_ANY,"","","",5); sc.schedStart=22*60; sc.schedEnd=6*60; sc.schedDays=0;
  struct tm t={0}; t.tm_hour=23; t.tm_wday=2; CHECK(fwp_sched_active(&sc,&t),"overnight active 23:00"); t.tm_hour=3; CHECK(fwp_sched_active(&sc,&t),"overnight active 03:00");
  t.tm_hour=12; CHECK(!fwp_sched_active(&sc,&t),"inactive noon"); sc.schedDays=1<<6; sc.schedStart=sc.schedEnd=0; t.tm_wday=6; CHECK(fwp_sched_active(&sc,&t),"saturday only"); t.tm_wday=1; CHECK(!fwp_sched_active(&sc,&t),"monday not");
  FwpRule v6=mk("v6",FWP_BLOCK,FWP_OUT,FWP_ANY,"","","2001:db8::1",5); FwpConn c6={0}; c6.dir=FWP_OUT; snprintf(c6.remoteIp,48,"2001:db8::1"); CHECK(fwp_rule_matches(&v6,&c6),"ipv6 match");

  /* log parser */
  FwpLogEntry e; const char *ln="2026-10-05 02:15:01 DROP TCP 192.168.1.5 142.250.1.1 51234 443 60 S 123 0 64240 - - - SEND 4216";
  CHECK(fwp_parse_log_line(ln,&e),"log parse"); CHECK(strcmp(e.action,"DROP")==0&&e.dport==443&&e.pid==4216&&strcmp(e.dst,"142.250.1.1")==0,"log fields");
  CHECK(!fwp_parse_log_line("#Fields: date time action",&e),"header skipped"); CHECK(!fwp_parse_log_line("garbage",&e),"garbage");
  const char *ln2="2026-10-05 02:15:02 ALLOW UDP 10.0.0.2 8.8.8.8 5353 53 40 - - - - - - - SEND"; CHECK(fwp_parse_log_line(ln2,&e)&&e.pid==0,"no pid column");
  fwp_parse_log_line(ln,&e); CHECK(fwp_log_matches(&e,"drop",NULL)&&fwp_log_matches(&e,"142.250",NULL)&&fwp_log_matches(&e,"chrome","Chrome.exe")&&!fwp_log_matches(&e,"allow","x"),"log filter");

  /* process tree incl. cycle */
  unsigned pid[]={1,10,11,12,13,20,30}, ppid[]={0,1,10,10,12,1,30}; unsigned d[16];
  int dn=fwp_descendants(pid,ppid,7,10,d,16); CHECK(dn==4,"subtree of 10 = 10,11,12,13");
  unsigned cp[]={5,6}, cpp[]={6,5}; dn=fwp_descendants(cp,cpp,2,5,d,16); CHECK(dn==2,"cycle safe");
  dn=fwp_descendants(pid,ppid,7,1,d,3); CHECK(dn==3,"maxOut respected");

  /* adaptive baseline */
  static FwpBaseline bl; memset(&bl,0,sizeof bl); bl.learnSeconds=600; bl.minObs=3; time_t t0=1000;
  CHECK(!fwp_baseline_observe(&bl,"Chrome.exe","142.250.1.1",443,t0),"learning: no alert");
  fwp_baseline_observe(&bl,"chrome.exe","142.250.9.9",443,t0+1); fwp_baseline_observe(&bl,"chrome.exe","142.250.5.5",443,t0+2);
  CHECK(!fwp_baseline_observe(&bl,"chrome.exe","203.0.113.5",443,t0+100),"still learning window");
  CHECK(!fwp_baseline_observe(&bl,"chrome.exe","142.250.77.1",443,t0+700),"same /16 + port known => not new");
  CHECK(fwp_baseline_observe(&bl,"chrome.exe","198.51.100.9",443,t0+701),"new /16 after maturity => alert");
  CHECK(!fwp_baseline_observe(&bl,"chrome.exe","198.51.100.10",443,t0+702),"alert once per bucket");
  CHECK(fwp_baseline_observe(&bl,"chrome.exe","142.250.1.1",4444,t0+703),"new port => alert");


  /* rule language */
  FwpRule pr; char er[200];
  CHECK(fwp_parse_rule_text("block out tcp app=\"C:\\Games\\g.exe\" rport=80,443 raddr=10.0.0.0/8 prio=10 group=Games name=\"Block game LAN\"",&pr,er,sizeof er),"parse full");
  CHECK(pr.action==FWP_BLOCK&&pr.dir==FWP_OUT&&pr.proto==FWP_TCP&&pr.priority==10&&strcmp(pr.name,"Block game LAN")==0&&strcmp(pr.program,"C:\\Games\\g.exe")==0&&strcmp(pr.remotePorts,"80,443")==0,"parse fields");
  CHECK(fwp_parse_rule_text("allow in udp lport=53 name=dns days=mon,tue time=22:00-06:00 iface=lan,wifi profile=private off",&pr,er,sizeof er)&&pr.schedDays==6&&pr.schedStart==1320&&pr.schedEnd==360&&pr.ifaceMask==3&&pr.profileMask==FWP_PROF_PRIVATE&&!pr.enabled,"parse sched/iface/off");
  CHECK(!fwp_parse_rule_text("block out tcp",&pr,er,sizeof er)&&strstr(er,"name"),"name required");
  CHECK(!fwp_parse_rule_text("out tcp name=x",&pr,er,sizeof er)&&strstr(er,"allow or block"),"action required");
  CHECK(!fwp_parse_rule_text("block out tcp rport=99999 name=x",&pr,er,sizeof er),"bad port rejected");
  CHECK(!fwp_parse_rule_text("block out tcp name=\"x\" app=\"C:\\a.exe\" & calc",&pr,er,sizeof er),"junk word rejected");
  CHECK(!fwp_parse_rule_text("block out tcp name=\"unterminated",&pr,er,sizeof er)&&strstr(er,"quote"),"unterminated quote");
  CHECK(!fwp_parse_rule_text("block out tcp name=x time=25:00-06:00",&pr,er,sizeof er),"bad time");
  CHECK(!fwp_parse_rule_text("block out tcp name=x days=funday",&pr,er,sizeof er),"bad day");
  CHECK(!fwp_parse_rule_text("block out tcp name=x bogus=1",&pr,er,sizeof er)&&strstr(er,"unknown key"),"unknown key");
  char ds[300]; fwp_parse_rule_text("block out tcp name=x rport=443",&pr,er,sizeof er); fwp_describe(&pr,ds,sizeof ds); CHECK(strstr(ds,"BLOCK out tcp")&&strstr(ds,"rport=443"),"describe");
  /* sandbox guard: too many allowed ports must fail, not truncate */
  FwpSandbox sb2; memset(&sb2,0,sizeof sb2); snprintf(sb2.program,260,"C:\\g.exe"); sb2.allowInternet=1; sb2.allowLan=1;
  snprintf(sb2.allowPorts,64,"1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59"); FwpRule o2[8];
  CHECK(fwp_sandbox_compile(&sb2,"G",o2,8)==-1,"over-long complement rejected instead of truncated");

  printf("%d/%d passed\n",total-fails,total); return fails?1:0; }
