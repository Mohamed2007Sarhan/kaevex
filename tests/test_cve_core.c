#include "../src/engines/cve_intel_core.h"
static int fails=0,total=0;
#define CHECK(c,m) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",m,__LINE__);} }while(0)

static const char *NVD =
"{\"cve\":{\"id\":\"CVE-2024-9999\",\"sourceIdentifier\":\"x@y\",\"published\":\"2024-05-01T10:00:00.000\","
"\"descriptions\":[{\"lang\":\"es\",\"value\":\"Desbordamiento\"},{\"lang\":\"en\",\"value\":\"Heap buffer overflow in Foo \\\"Bar\\\" allows remote code execution.\"}],"
"\"metrics\":{\"cvssMetricV31\":[{\"source\":\"nvd@nist.gov\",\"type\":\"Primary\",\"cvssData\":{\"version\":\"3.1\",\"baseScore\":8.8,\"baseSeverity\":\"HIGH\"},\"exploitabilityScore\":2.8}]},"
"\"configurations\":[{\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":["
"{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*\",\"versionEndExcluding\":\"124.0.6367.60\",\"matchCriteriaId\":\"A\"},"
"{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:igor_pavlov:7-zip:*:*:*:*:*:*:*:*\",\"versionStartIncluding\":\"20.0\",\"versionEndIncluding\":\"23.00\",\"matchCriteriaId\":\"B\"},"
"{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:vlc\\\\:org:vlc_media_player:3.0.20:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"C\"},"
"{\"vulnerable\":false,\"criteria\":\"cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"D\"}]}]}],"
"\"references\":[{\"url\":\"https://example.com\",\"source\":\"x\"}]}}";

int main(void){
  /* versions */
  CHECK(cvi_ver_cmp("1.2.3","1.2.10")<0,"1.2.3<1.2.10"); CHECK(cvi_ver_cmp("124.0.6367.60","124.0.6367.60")==0,"eq"); CHECK(cvi_ver_cmp("2.0","2.0.0.0")==0,"pad zeros");
  CHECK(cvi_ver_cmp("v131.0.6778.205","124.0")>0,"v prefix"); CHECK(cvi_ver_cmp("2.45.1.windows.1","2.45.1")>=0,"git style"); CHECK(cvi_ver_cmp("23.01","23.00")>0,"7zip");
  CHECK(!cvi_ver_has_digits("unknown")&&cvi_ver_has_digits("1"),"has digits");
  /* cpe */
  CviCpe c; CHECK(cvi_cpe_parse("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",&c)&&c.part=='a'&&!strcmp(c.vendor,"google")&&!strcmp(c.product,"chrome")&&!c.version[0],"cpe basic");
  CHECK(cvi_cpe_parse("cpe:2.3:a:vlc\\:org:vlc_media_player:3.0.20:*:*:*:*:*:*:*",&c)&&!strcmp(c.vendor,"vlc:org")&&!strcmp(c.version,"3.0.20"),"cpe escaped colon");
  CHECK(!cvi_cpe_parse("not a cpe",&c)&&!cvi_cpe_parse("cpe:2.3:a:onlyvendor",&c),"cpe invalid");
  CHECK(cvi_cpe_parse("cpe:2.3:a:notepad\\+\\+:notepad\\+\\+:*:*:*:*:*:*:*:*",&c)&&!strcmp(c.product,"notepad++"),"cpe plus");
  /* name matching: positives */
  CHECK(cvi_name_match("Google Chrome","Google LLC","google","chrome")==CVI_HIGH,"chrome HIGH");
  CHECK(cvi_name_match("7-Zip 23.01 (x64)","Igor Pavlov","igor_pavlov","7-zip")>=CVI_MED,"7zip");
  CHECK(cvi_name_match("Microsoft Edge","Microsoft Corporation","microsoft","edge_chromium")>=CVI_MED,"edge ~ edge_chromium");
  CHECK(cvi_name_match("Python 3.12.1 (64-bit)","Python Software Foundation","python","python")==CVI_HIGH,"python");
  CHECK(cvi_name_match("Notepad++ (64-bit x64)","Notepad++ Team","notepad++","notepad++")==CVI_HIGH,"notepad++");
  CHECK(cvi_name_match("Visual Studio Code","Microsoft","microsoft","visual_studio_code")==CVI_HIGH,"vscode exact");
  CHECK(cvi_name_match("VLC media player","VideoLAN","videolan","vlc_media_player")>=CVI_MED,"vlc");
  /* negatives: classic false positives */
  CHECK(cvi_name_match("Microsoft Visual Studio Code","Microsoft","microsoft","visual_studio")==CVI_NO,"vscode != visual_studio");
  CHECK(cvi_name_match("Windows Driver Package - Intel (e1d)","Intel","microsoft","windows")==CVI_NO,"generic 'windows' never matches");
  CHECK(cvi_name_match("Google Earth Pro","Google","google","chrome")==CVI_NO,"different google product");
  CHECK(cvi_name_match("Microsoft Office Professional","Microsoft","microsoft","office")<=CVI_MED,"generic office capped");
  CHECK(cvi_name_match("Java 8 Update 401","Oracle","oracle","jre")==CVI_NO,"unknown product");
  CHECK(cvi_name_match("Chromium","The Chromium Authors","google","chrome")==CVI_NO || cvi_name_match("Chromium","x","google","chrome")<=CVI_LOW,"chromium vs chrome not high");
  /* KEV candidates */
  CHECK(cvi_kev_candidate("Google Chrome","Google LLC","Google","Chromium V8"),"kev chrome~chromium");
  CHECK(!cvi_kev_candidate("Google Earth Pro","Google","Google","Chromium V8"),"kev unrelated google product");
  CHECK(cvi_kev_candidate("7-Zip 23.01 (x64)","Igor Pavlov","7-Zip","7-Zip"),"kev 7zip");
  CHECK(!cvi_kev_candidate("Windows Update Assistant","Microsoft","Microsoft","Windows"),"kev generic windows");

  /* NVD record */
  CviCve cv; CHECK(cvi_parse_nvd_cve(NVD,&cv),"parse nvd");
  CHECK(!strcmp(cv.id,"CVE-2024-9999")&&!strcmp(cv.published,"2024-05-01")&&cv.score10==88&&!strcmp(cv.severity,"HIGH"),"nvd id/score");
  CHECK(strstr(cv.summary,"Heap buffer overflow")&&strstr(cv.summary,"\"Bar\""),"english description + unescape");
  CHECK(cv.nr==3,"3 vulnerable app ranges (OS entry skipped)"); 
  CHECK(!strcmp(cv.r[0].vendor,"google")&&!strcmp(cv.r[0].endExc,"124.0.6367.60"),"range0"); CHECK(!strcmp(cv.r[1].startInc,"20.0")&&!strcmp(cv.r[1].endInc,"23.00"),"range1");
  CHECK(!strcmp(cv.r[2].exact,"3.0.20")&&!strcmp(cv.r[2].vendor,"vlc:org"),"range2 exact");
  /* matching with versions */
  CviHit h;
  CHECK(cvi_match(&cv,"Google Chrome","Google LLC","123.0.6312.58",&h)==CVI_HIGH&&!strcmp(h.fixed,"124.0.6367.60"),"chrome 123 affected, fixed in 124.0.6367.60");
  CHECK(cvi_match(&cv,"Google Chrome","Google LLC","124.0.6367.60",&h)==CVI_NO,"chrome at fixed version NOT affected");
  CHECK(cvi_match(&cv,"Google Chrome","Google LLC","131.0.6778.205",&h)==CVI_NO,"chrome newer not affected");
  CHECK(cvi_match(&cv,"Google Chrome","Google LLC","",&h)==CVI_NO,"unknown version never flagged");
  CHECK(cvi_match(&cv,"7-Zip 23.00 (x64)","Igor Pavlov","23.00",&h)>=CVI_MED,"7zip 23.00 within inclusive end");
  CHECK(cvi_match(&cv,"7-Zip 23.01 (x64)","Igor Pavlov","23.01",&h)==CVI_NO,"7zip 23.01 above range");
  CHECK(cvi_match(&cv,"7-Zip","Igor Pavlov","19.00",&h)==CVI_NO,"7zip below start");
  CHECK(cvi_match(&cv,"Firefox","Mozilla","100.0",&h)==CVI_NO,"other app");
  /* all-versions range is weak evidence */
  CviCve all; memset(&all,0,sizeof all); snprintf(all.id,24,"CVE-1"); all.nr=1; snprintf(all.r[0].vendor,40,"google"); snprintf(all.r[0].product,40,"chrome");
  CHECK(cvi_match(&all,"Google Chrome","Google","1.0",&h)==CVI_LOW&&h.allVersions,"all versions capped LOW");

  /* KEV feed */
  const char *KEV="{\"title\":\"CISA\",\"catalogVersion\":\"2026.10.01\",\"count\":2,\"vulnerabilities\":["
   "{\"cveID\":\"CVE-2024-4947\",\"vendorProject\":\"Google\",\"product\":\"Chromium V8\",\"vulnerabilityName\":\"Google Chromium V8 Type Confusion\",\"dateAdded\":\"2024-05-16\",\"shortDescription\":\"x\",\"requiredAction\":\"Apply mitigations per vendor instructions, \\\"or\\\" discontinue.\",\"dueDate\":\"2024-06-06\",\"knownRansomwareCampaignUse\":\"Unknown\",\"notes\":\"\",\"cwes\":[\"CWE-843\"]},"
   "{\"cveID\":\"CVE-2023-38831\",\"vendorProject\":\"RARLAB\",\"product\":\"WinRAR\",\"vulnerabilityName\":\"WinRAR Code Execution\",\"dateAdded\":\"2023-08-24\",\"requiredAction\":\"Apply updates.\",\"knownRansomwareCampaignUse\":\"Known\"}]}";
  CviKev kev[8]; int nk=cvi_parse_kev(KEV,kev,8); CHECK(nk==2,"kev count"); CHECK(!strcmp(kev[0].cve,"CVE-2024-4947")&&!strcmp(kev[0].vendor,"Google")&&strstr(kev[0].action,"\"or\""),"kev fields"); CHECK(!kev[0].ransomware&&kev[1].ransomware,"ransomware flag");

  /* AI plan: closed world */
  char allowed[3][100]={"Google.Chrome","7zip.7zip","Mozilla.Firefox"}; CviPlan pl;
  CHECK(cvi_parse_plan("{\"action\":\"UPGRADE_WINGET\",\"winget_id\":\"Google.Chrome\",\"reason\":\"patch\",\"steps\":[\"restart browser\"]}",allowed,3,&pl)&&pl.action==CVI_ACT_UPGRADE&&!strcmp(pl.wingetId,"Google.Chrome")&&pl.nsteps==1,"valid plan");
  CHECK(cvi_parse_plan("Sure! Here is the plan:\n```json\n{\"action\":\"UPGRADE_WINGET\",\"winget_id\":\"7zip.7zip\",\"reason\":\"r\"}\n```\nHope it helps",allowed,3,&pl)&&pl.action==CVI_ACT_UPGRADE,"fenced json accepted");
  CHECK(!cvi_parse_plan("{\"action\":\"UPGRADE_WINGET\",\"winget_id\":\"Evil.Package\"}",allowed,3,&pl)&&pl.action==CVI_ACT_MANUAL,"id not offered -> rejected");
  CHECK(!cvi_parse_plan("{\"action\":\"UPGRADE_WINGET\",\"winget_id\":\"Google.Chrome & calc.exe\"}",allowed,3,&pl)&&pl.action==CVI_ACT_MANUAL&&!pl.wingetId[0],"injection id rejected");
  char evil[1][100]={"a b"}; CHECK(!cvi_parse_plan("{\"action\":\"UPGRADE_WINGET\",\"winget_id\":\"a b\"}",evil,1,&pl),"invalid id even if 'allowed'");
  CHECK(!cvi_parse_plan("{\"action\":\"RUN_COMMAND\",\"command\":\"del /s C:\\\\\"}",allowed,3,&pl)&&pl.action==CVI_ACT_MANUAL&&!strstr(pl.reason,"del /s"),"arbitrary command action rejected");
  CHECK(!cvi_parse_plan("I think you should upgrade it.",allowed,3,&pl)&&pl.action==CVI_ACT_MANUAL,"no json -> manual");
  CHECK(cvi_parse_plan("{\"action\":\"CONTAIN_NETWORK\",\"reason\":\"no patch\"}",allowed,3,&pl)&&pl.action==CVI_ACT_CONTAIN,"contain ok");
  CHECK(cvi_parse_plan("{\"action\":\"none\"}",allowed,3,&pl)&&pl.action==CVI_ACT_NONE,"none ok (case-insens)");
  CHECK(cvi_valid_winget_id("Microsoft.VisualStudioCode")&&cvi_valid_winget_id("Notepad++.Notepad++")&&!cvi_valid_winget_id("nodots")&&!cvi_valid_winget_id("a..b")&&!cvi_valid_winget_id(".a.b")&&!cvi_valid_winget_id("a.b;c"),"winget id validation");

  /* winget export + candidates + fallback */
  const char *EX="{\"$schema\":\"x\",\"Sources\":[{\"Packages\":[{\"PackageIdentifier\":\"Google.Chrome\"},{\"PackageIdentifier\":\"7zip.7zip\"},{\"PackageIdentifier\":\"Microsoft.VCRedist.2015+.x64\"},{\"PackageIdentifier\":\"Google.Chrome\"},{\"PackageIdentifier\":\"bad id\"}],\"SourceDetails\":{\"Name\":\"winget\"}}]}";
  static char ids[64][100]; int ni=cvi_parse_winget_export(EX,ids,64); CHECK(ni==3,"export parse (dedupe, drop invalid)");
  char cands[5][100]; int nc=cvi_candidates("Google Chrome","Google LLC",ids,ni,cands,5); CHECK(nc==1&&!strcmp(cands[0],"Google.Chrome"),"candidate chrome");
  nc=cvi_candidates("7-Zip 23.01 (x64)","Igor Pavlov",ids,ni,cands,5); CHECK(nc==1&&!strcmp(cands[0],"7zip.7zip"),"candidate 7zip");
  nc=cvi_candidates("Totally Unrelated App","Acme",ids,ni,cands,5); CHECK(nc==0,"no candidate for unrelated");
  char one[1][100]={"Google.Chrome"}; cvi_fallback_plan(1,0,one,1,&pl); CHECK(pl.action==CVI_ACT_UPGRADE&&!pl.fromAi,"fallback upgrade");
  cvi_fallback_plan(1,1,one,0,&pl); CHECK(pl.action==CVI_ACT_CONTAIN,"fallback contain for KEV w/o package"); cvi_fallback_plan(0,0,one,0,&pl); CHECK(pl.action==CVI_ACT_MANUAL,"fallback manual");
  printf("%d/%d passed\n",total-fails,total); return fails?1:0; }
