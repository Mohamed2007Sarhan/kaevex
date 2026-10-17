#include "../src/engines/ai_core.h"
static int fails=0, total=0;
#define CHECK(c,msg) do{total++; if(!(c)){fails++;printf("FAIL: %s (line %d)\n",msg,__LINE__);} }while(0)

int main(void){
  char out[4096], err[512];

  /* 1. escape: the old code broke on backslashes (Windows paths) */
  char *e = kvai_escape_alloc("scan C:\\Windows\\System32 \"x\"\n\ttab");
  CHECK(strcmp(e,"scan C:\\\\Windows\\\\System32 \\\"x\\\"\\n\\ttab")==0,"escape backslash/quote/newline");
  free(e);
  e = kvai_escape_alloc("bad\xff\xfe byte");           /* ANSI bytes that are not UTF-8 */
  CHECK(kvai_is_valid_utf8(e),"invalid bytes sanitized to valid UTF-8");
  free(e);
  e = kvai_escape_alloc("مرحبا");                       /* valid Arabic UTF-8 preserved */
  CHECK(strcmp(e,"مرحبا")==0,"arabic preserved");
  free(e);
  e = kvai_escape_alloc("a\x01z");
  CHECK(strcmp(e,"a\\u0001z")==0,"control char escaped");
  free(e);

  /* 2. request body is itself parseable by our reader and long prompts are not truncated */
  char *big = malloc(20000); memset(big,'A',19999); big[19999]=0;
  char *body = kvai_build_request("deepseek-ai/DeepSeek-V4-Pro","sys \\ \"q\"",big,0.7f,4096);
  CHECK(body && strlen(body)>19999,"long prompt not truncated");
  const char *m = kvai_find_key(body,"model"); CHECK(m&&*m=='"',"model key found");
  kvai_read_str(m,out,sizeof(out)); CHECK(strcmp(out,"deepseek-ai/DeepSeek-V4-Pro")==0,"model value");
  const char *mt = kvai_find_key(body,"max_tokens"); CHECK(mt&&atoi(mt)==4096,"max_tokens");
  free(body); free(big);

  /* 3. normal success */
  const char *ok1="{\"id\":\"x\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"Hello\\nWorld \\\"q\\\" \\u0645\\u0631\\u062d\\u0628\\u0627\"},\"finish_reason\":\"stop\"}]}";
  CHECK(kvai_parse_response(200,ok1,0,out,sizeof(out),err,sizeof(err)),"parse ok");
  CHECK(strcmp(out,"Hello\nWorld \"q\" مرحبا")==0,"decoded unicode/escapes");

  /* 4. reasoning_content comes BEFORE content, and mentions "content" in text */
  const char *ok2="{\"choices\":[{\"message\":{\"role\":\"assistant\",\"reasoning_content\":\"think \\\"content\\\": fake\",\"content\":\"REAL\"},\"finish_reason\":\"stop\"}]}";
  CHECK(kvai_parse_response(200,ok2,0,out,sizeof(out),err,sizeof(err)) && strcmp(out,"REAL")==0,"not fooled by reasoning text");

  /* 5. reasoning model ran out of tokens: content null */
  const char *r1="{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":null,\"reasoning_content\":\"long...\"},\"finish_reason\":\"length\"}]}";
  CHECK(!kvai_parse_response(200,r1,0,out,sizeof(out),err,sizeof(err)),"null content = failure");
  CHECK(strstr(err,"raise max tokens")!=NULL,"explains token exhaustion");
  printf("  e: %s\n",err);

  /* 6. provider error shapes */
  const char *t401="{\"id\":\"z\",\"error\":{\"message\":\"Invalid API key provided\",\"type\":\"invalid_request_error\",\"code\":\"invalid_api_key\"}}";
  CHECK(!kvai_parse_response(401,t401,0,out,sizeof(out),err,sizeof(err)),"401 fails");
  CHECK(strstr(err,"HTTP 401")&&strstr(err,"Invalid API key")&&strstr(err,"provider-specific"),"401 msg+hint");
  printf("  e: %s\n",err);
  const char *t404="{\"error\":{\"message\":\"Unable to access model deepseek-ai/DeepSeek-V4-Pro-0813\",\"type\":\"model_not_found\"}}";
  kvai_parse_response(404,t404,0,out,sizeof(out),err,sizeof(err));
  CHECK(strstr(err,"model_not_found")==NULL && strstr(err,"Unable to access model")&&strstr(err,"retired"),"404 msg+hint");
  printf("  e: %s\n",err);
  const char *nv="{\"status\":401,\"title\":\"Unauthorized\",\"detail\":\"Authentication failed\"}";
  kvai_parse_response(401,nv,2,out,sizeof(out),err,sizeof(err));
  CHECK(strstr(err,"Authentication failed")!=NULL,"nvidia detail shape");
  printf("  e: %s\n",err);
  kvai_parse_response(429,"{\"error\":{\"message\":\"Rate limit reached\"}}",1,out,sizeof(out),err,sizeof(err));
  CHECK(strstr(err,"Rate limit")&&strstr(err,"quota"),"429");
  kvai_parse_response(503,"<html>bad gateway</html>",0,out,sizeof(out),err,sizeof(err));
  CHECK(strstr(err,"HTTP 503")&&strstr(err,"Provider-side"),"html error body");
  CHECK(!kvai_parse_response(200,"",0,out,sizeof(out),err,sizeof(err)) && strstr(err,"empty"),"empty body");

  /* 7. surrogate pair emoji, truncated JSON must not crash */
  const char *em="{\"choices\":[{\"message\":{\"content\":\"hi \\ud83d\\ude00\"}}]}";
  kvai_parse_response(200,em,0,out,sizeof(out),err,sizeof(err));
  CHECK(strcmp(out,"hi \xF0\x9F\x98\x80")==0,"surrogate pair");
  kvai_parse_response(200,"{\"choices\":[{\"message\":{\"content\":\"unterminated",0,out,sizeof(out),err,sizeof(err));
  CHECK(1,"truncated json no crash");
  char tiny[8]; kvai_parse_response(200,ok1,0,tiny,sizeof(tiny),err,sizeof(err));
  CHECK(strlen(tiny)<8,"output buffer bound respected");

  printf("%d/%d passed\n",total-fails,total);
  return fails?1:0;
}
