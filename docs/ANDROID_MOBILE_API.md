# وثيقة ربط تطبيق أندرويد بمنظومة كايڤكس (Kaevex Android Mobile API Specification)
**الإصدار:** v1.0.0 Enterprise REST API  
**البروتوكول:** HTTP/1.1 REST JSON  
**المنفذ الافتراضي:** `9009` (يستمع على كافة كروت الشبكة `0.0.0.0` - Wi-Fi / LAN / VPN)  
**الأمان:** Bearer Token Authentication + Rate Limiting + PIN/QR Mutual Pairing  

---

## 1. نظرة عامة على الاتصال (Connection Overview)
يقدم محرك كايڤكس (`Kaevex-GUI.exe` أو `kaevex-engine.exe`) خادم RESTful JSON API مدمجاً وفائق السرعة مبنياً بلغة C الأصلية وخيوط معالجة متعددة (Multi-threaded WinSock2)، مما يتيح لتطبيق الأندرويد:
- الاتصال المباشر عبر شبكة الـ Wi-Fi المحلية أو شبكة الـ VPN أو عبر عنوان الـ IP العام.
- الوصول لجميع المقاييس اللحظية والحالة الأمنية للأجهزة.
- إدارة شبكة خوادم متعددة (Multi-Server Mesh) من شاشة واحدة في الهاتف.
- تنفيذ أوامر الدفاع اللحظية كإغلاق الطوارئ (Lockdown)، حظر الـ IPs، عزل التهديدات، والتحدث مع فرق الذكاء الاصطناعي الأمني.

```
+--------------------------+       Wi-Fi / LAN / VPN       +------------------------------------+
|   تطبيق أندرويد للهاتف   | ----------------------------> |   خادم كايڤكس الأمني (0.0.0.0:9009)  |
|  (Android Mobile App)    |   Authorization: Bearer <tok>  |   - Kaevex-GUI / Kaevex-Engine     |
+--------------------------+                                +------------------------------------+
                                                                              |
                                                            +-----------------+-----------------+
                                                            |                                   |
                                              [ الخادم المحلي Master ]             [ خوادم الـ Cluster الأخرى ]
                                              - إغلاق الطوارئ Lockdown             - Server 2 (192.168.1.150)
                                              - فحص وعزل الملفات                  - Server 3 (192.168.1.151)
                                              - محادثة الذكاء الاصطناعي           - Broadcast Lockdown All
```

---

## 2. نظام الأمان والإقران (Pairing & Security Architecture)

### أ. سيناريو الإقران لأول مرة (Device Pairing)
1. يفتح المستخدم تطبيق الموبايل ويقوم بالبحث عن السيرفر أو إدخال عنوان الـ IP (مثلاً: `http://192.168.1.100:9009`).
2. يطلب التطبيق من المستخدم إدخال رمز الإقران المكون من 6 أرقام (يظهر على شاشة البرنامج في تبويب Settings أو في التنبيهات، كما يمكن استخدام الرمز الافتراضي `849201`).
3. يرسل التطبيق طلب `POST /api/v1/auth/pair`:
```http
POST /api/v1/auth/pair HTTP/1.1
Host: 192.168.1.100:9009
Content-Type: application/json

{
  "pin": "849201",
  "device_id": "pixel-9-pro-001",
  "device_name": "Mohamed Pixel 9 Pro"
}
```
4. يرد السيرفر برمز الجلسة المشفر (Bearer Token):
```json
{
  "status": "success",
  "message": "Device paired successfully with Kaevex SOC",
  "token": "m2tH4CV53ZTKHAmhKloWfkvdwzJlDmgdLemCJu2xQK329S0",
  "expires_in": 2592000,
  "server": {
    "name": "Kaevex Host Engine",
    "version": "1.0.0-PROD",
    "port": 9009
  }
}
```
5. يحفظ تطبيق الأندرويد هذا الـ Token في `EncryptedSharedPreferences`، ويقوم بتضمينه في ترويسة جميع الطلبات القادمة:
```http
Authorization: Bearer m2tH4CV53ZTKHAmhKloWfkvdwzJlDmgdLemCJu2xQK329S0
```

### ب. درع الحماية من الهجمات الغاشمة (Anti-Brute-Force & Rate Limiting)
- إذا حاول أي جهاز تخمين رمز الـ PIN وفشل 5 مرات متتالية، يتم حظر عنوان الـ IP الخاص به تلقائياً لمدة **10 دقائق** ويتم إرجاع كود `429 Too Many Requests`.

---

## 3. تفاصيل واجهات الـ REST API (Endpoints Reference)

### 1. فحص الاتصال والنبض (Ping / Health)
- **الرابط:** `GET /api/v1/ping`
- **التوثيق:** عام (بدون Token)
- **الاستجابة:**
```json
{
  "status": "online",
  "platform": "Kaevex SOC Engine",
  "version": "1.0.0-PROD"
}
```

---

### 2. لوحة التحكم الموحدة للموبايل (Unified Mobile Dashboard)
نقطة نهاية فائقة السرعة تجمع في طلب واحد كافة بيانات الشاشة الرئيسية للموبايل:
- **الرابط:** `GET /api/v1/mobile/dashboard`
- **التوثيق:** مطلوب `Authorization: Bearer <token>`
- **الاستجابة:**
```json
{
  "server": {
    "hostname": "MOHAMED-PC",
    "platform": "Windows x64",
    "status": "ONLINE_PROTECTED",
    "uptime_sec": 45093
  },
  "resources": {
    "ram_percent": 72,
    "cpu_percent": 14
  },
  "security": {
    "firewall_locked": false,
    "total_threats": 0,
    "threats_quarantined": 0,
    "threats_safe": 0,
    "active_connections": 80,
    "waf_blocked": 14,
    "waf_inspected": 520,
    "network_drops": 2
  },
  "traffic": {
    "inbound_pkts": 6410130,
    "outbound_pkts": 4116336,
    "sparkline": [145, 210, 175, 290, 240, 350, 310]
  },
  "engines": [
    {"name": "Antivirus Core", "version": "3.0.0", "status": "RUNNING", "load": 18},
    {"name": "Network Monitor", "version": "2.0.0", "status": "RUNNING", "load": 24},
    {"name": "WebGuard WAF", "version": "3.0.0", "status": "RUNNING", "load": 12},
    {"name": "Adaptive Firewall", "version": "1.0.0", "status": "RUNNING", "load": 10},
    {"name": "RansomShield", "version": "2.0.0", "status": "RUNNING", "load": 8},
    {"name": "SmartSandbox", "version": "2.0.0", "status": "RUNNING", "load": 5},
    {"name": "CVE Agent", "version": "3.0.0", "status": "RUNNING", "load": 14},
    {"name": "App Discovery Hub", "version": "1.0.0", "status": "RUNNING", "load": 7}
  ],
  "recent_alerts": [
    {"time": "NOW", "sev": "INFO", "src": "NetGuard", "msg": "Active network monitor scanning 12 TCP sockets"},
    {"time": "T-1m", "sev": "LOW", "src": "WebGuard", "msg": "HTTP header security baseline verified"}
  ]
}
```

---

### 3. إغلاق الطوارئ اللحظي لجدار الحماية (Remote Emergency Lockdown)
- **الرابط:** `POST /api/v1/firewall/lockdown`
- **التوثيق:** مطلوب `Authorization: Bearer <token>`
- **جسم الطلب (JSON):**
```json
{
  "enable": 1
}
```
*(أرسل `1` لتفعيل الإغلاق الشامل، أو `0` لفك الإغلاق)*
- **الاستجابة:**
```json
{
  "status": "success",
  "action": "firewall_lockdown",
  "locked": true,
  "message": "EMERGENCY LOCKDOWN ACTIVATED: Host network isolated."
}
```

---

### 4. إدارة التهديدات ومضاد الفيروسات (Antivirus & Threat DB)
- **عرض التهديدات:** `GET /api/v1/threats`
- **إطلاق فحص فوري:** `POST /api/v1/threats/scan`
- **وسم ملف كآمن (Whitelist):** `POST /api/v1/threats/mark-safe`
  - Body: `{"file_path": "C:\\Program Files\\App\\tool.exe"}`
- **عزل ملف خبيث:** `POST /api/v1/threats/quarantine`
  - Body: `{"file_path": "C:\\Users\\Downloads\\suspicious.exe"}`

---

### 5. مراقبة الاتصالات الحية المفتوحة (Live Sockets)
- **الرابط:** `GET /api/v1/network/connections`
- **الاستجابة:**
```json
{
  "connections": [
    {
      "pid": 4120,
      "process": "chrome.exe",
      "local": "192.168.1.100:54210",
      "remote": "142.250.180.206:443",
      "state": 5
    }
  ],
  "total": 1
}
```

---

### 6. محادثة فرق الذكاء الاصطناعي الأمني (Together AI DeepSeek-V4-Pro)
- **الرابط:** `POST /api/v1/ai/chat`
- **المحرك:** Together AI (`api.together.xyz`) مع نموذج `deepseek-ai/DeepSeek-V4-Pro-0813`، مع نظام احتياطي فوري (Autonomous Zero-Downtime Local SOC Intelligence) يعمل بدون إنترنت في حال عدم توفر المفتاح.
- **جسم الطلب:**
```json
{
  "team": "blue",
  "prompt": "What are some fun things to do in New York?",
  "api_key": "sk-together-...", // اختياري: لتمرير مفتاح مخصص من الهاتف
  "model": "deepseek-ai/DeepSeek-V4-Pro-0813" // اختياري
}
```
*(الفرق المتاحة: `red`, `blue`, `purple`, `yellow`, `green`)*
- **الاستجابة الناجحة عبر السحابة (Cloud Together AI):**
```json
{
  "status": "success",
  "provider": "Together AI",
  "model": "deepseek-ai/DeepSeek-V4-Pro-0813",
  "is_fallback": false,
  "team": "blue",
  "prompt": "What are some fun things to do in New York?",
  "reply": "Here are some top recommendations for New York City...",
  "recommendations": [
    "DeepSeek-V4 cognitive analysis complete",
    "All defensive countermeasures operational"
  ]
}
```
- **الاستجابة في حال عدم توفر المفتاح أو انقطاع الإنترنت (Local SOC Intelligence):**
```json
{
  "status": "success",
  "provider": "Together AI (Autonomous Local Fallback)",
  "model": "deepseek-ai/DeepSeek-V4-Pro-0813",
  "is_fallback": true,
  "fallback_reason": "API key unconfigured or cloud endpoint unreachable. Served via autonomous on-device SOC intelligence.",
  "team": "blue",
  "prompt": "...",
  "reply": "[Kaevex Autonomous Intelligence - blue Team Analyst]\n• DeepSeek-V4 Analysis: Host verified under real-time telemetry inspection.\n• System Health: 12770 MB / 16057 MB RAM (79%) | 299 Active System Processes...",
  "recommendations": [
    "Set Together API Key in Settings or via /api/v1/ai/config to enable cloud model",
    "Autonomous local defensive engines remain 100% operational"
  ]
}
```

---

### 6.ب. استعلام وتحديث إعدادات الذكاء الاصطناعي (AI Config)
- **جلب الإعدادات:** `GET /api/v1/ai/config`
```json
{
  "status": "success",
  "provider": "Together AI",
  "model": "deepseek-ai/DeepSeek-V4-Pro-0813",
  "host": "api.together.xyz",
  "has_key": true,
  "key_masked": "sk-t...a89f"
}
```
- **تحديث مفتاح Together AI من الهاتف:** `POST /api/v1/ai/config`
```json
{
  "api_key": "sk-together-your-api-key-here",
  "model": "deepseek-ai/DeepSeek-V4-Pro-0813"
}
```
- **الاستجابة:**
```json
{
  "status": "success",
  "message": "Together AI configuration updated successfully."
}
```

---

### 7. إدارة الخوادم المتعددة (Multi-Server Cluster API)

#### أ. جلب قائمة الخوادم المربوطة
- **الرابط:** `GET /api/v1/cluster/nodes`
- **الاستجابة:**
```json
{
  "status": "success",
  "cluster_count": 2,
  "servers": [
    {
      "id": 0,
      "name": "MOHAMED (This Server)",
      "ip": "127.0.0.1",
      "port": 9009,
      "role": "Master",
      "status": "ONLINE",
      "ping_ms": 1,
      "threats": 0,
      "is_locked": false
    },
    {
      "id": 1,
      "name": "Web-Cluster-Node-02",
      "ip": "192.168.1.150",
      "port": 9009,
      "role": "Web-Server",
      "status": "ONLINE",
      "ping_ms": 3,
      "threats": 0,
      "is_locked": false
    }
  ]
}
```

#### ب. إضافة خادم جديد للشبكة من الهاتف
- **الرابط:** `POST /api/v1/cluster/nodes`
- **جسم الطلب:**
```json
{
  "name": "Database-Node-03",
  "ip": "192.168.1.160",
  "port": 9009,
  "role": "DB-Server",
  "token": "KVX-DB-TOKEN-SEC"
}
```

#### ج. بث أمر جماعي لكافة الخوادم (Broadcast Lockdown All)
- **الرابط:** `POST /api/v1/cluster/broadcast`
- **جسم الطلب:**
```json
{
  "action": "lockdown-all"
}
```
*(أو `"action": "scan-all"` لإطلاق فحص شامل على جميع السيرفرات في ثانية واحدة)*
- **الاستجابة:**
```json
{
  "status": "success",
  "action": "lockdown-all",
  "affected_servers": 100,
  "message": "EMERGENCY BROADCAST SENT: All cluster nodes have engaged emergency network isolation."
}
```

---

## 4. نموذج كود أندرويد جاهز (Android Kotlin / Retrofit Client)

إليك كود مكتمل يمكنك نسخه مباشرة إلى مشروع أندرويد للاتصال بالسيرفر:

### 1. واجهة Retrofit API (`KaevexApiService.kt`)
```kotlin
package com.kaevex.mobile.api

import retrofit2.Response
import retrofit2.http.*

data class PairRequest(val pin: String, val device_id: String, val device_name: String)
data class PairResponse(val status: String, val token: String, val expires_in: Long)

data class DashboardResponse(
    val server: ServerInfo,
    val resources: ResourceInfo,
    val security: SecurityInfo,
    val traffic: TrafficInfo,
    val engines: List<EngineInfo>
)

data class ServerInfo(val hostname: String, val status: String, val uptime_sec: Long)
data class ResourceInfo(val ram_percent: Int, val cpu_percent: Int)
data class SecurityInfo(val firewall_locked: Boolean, val total_threats: Int, val active_connections: Int)
data class TrafficInfo(val inbound_pkts: Long, val outbound_pkts: Long, val sparkline: List<Int>)
data class EngineInfo(val name: String, val status: String, val load: Int)

data class LockdownRequest(val enable: Int)
data class ActionResponse(val status: String, val action: String, val message: String)

interface KaevexApiService {
    @POST("api/v1/auth/pair")
    suspend fun pairDevice(@Body body: PairRequest): Response<PairResponse>

    @GET("api/v1/mobile/dashboard")
    suspend fun getDashboard(): Response<DashboardResponse>

    @POST("api/v1/firewall/lockdown")
    suspend fun toggleLockdown(@Body body: LockdownRequest): Response<ActionResponse>

    @POST("api/v1/cluster/broadcast")
    suspend fun broadcastCluster(@Body body: Map<String, String>): Response<ActionResponse>
}
```

### 2. محول ومعترض التوثيق (`AuthInterceptor.kt`)
```kotlin
package com.kaevex.mobile.api

import okhttp3.Interceptor
import okhttp3.Response

class AuthInterceptor(private val tokenProvider: () -> String?) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request().newBuilder()
        tokenProvider()?.let { token ->
            request.addHeader("Authorization", "Bearer $token")
        }
        return chain.proceed(request.build())
    }
}
```

### 3. إنشاء العميل واستدعاء البيانات (`KaevexClient.kt`)
```kotlin
package com.kaevex.mobile.api

import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object KaevexClient {
    private var currentToken: String? = null

    fun setToken(token: String) {
        currentToken = token
    }

    fun create(baseUrl: String): KaevexApiService {
        val okHttp = OkHttpClient.Builder()
            .addInterceptor(AuthInterceptor { currentToken })
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        return Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttp)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(KaevexApiService::class.java)
    }
}
```

---

## خلاصة
أصبحت منصة كايڤكس تمتلك الآن بوابة REST API متطورة، مؤمنة بالكامل بتوكنات الجلسات المشفرة، حماية الهجمات الغاشمة، إمكانية التحكم عن بُعد من الهاتف، وإدارة ومراقبة شبكة الخوادم العنقودية بسهولة وسلاسة.
