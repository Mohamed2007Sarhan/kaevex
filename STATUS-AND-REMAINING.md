# Kaevex — الحالة الحالية واللي فاضل (بصراحة)

> اتختبر كله على Linux (Wine للـ Windows). **مفيش أي جزء اتجرّب على Windows حقيقي أو Android حقيقي.**

## 1) اتعمل واتجرّب فعلاً
| الجزء | اتجرّب إزاي |
|---|---|
| **WAF حقيقي** (`waf_core.h`): تطبيع (URL مرتين/3، HTML entities، unicode، تعليقات SQL، NUL) + 25 فئة: SQLi, XSS, XXE+XML bombs, Path Traversal, LFI/RFI, Command Injection, SSRF, SSTI, NoSQL/LDAP/XPath, CRLF, Log4Shell, Shellshock, OGNL/Spring4Shell, Deserialization (Java/PHP/.NET/YAML), Prototype Pollution, Webshell upload, Sensitive-file probing, Scanner fingerprints, Request Smuggling, Encoding evasion, Open Redirect, GraphQL | 165 اختبار + ASan: **98/98 هجوم اتكشف، 53/53 طلب سليم عدّى** |
| **WAF reverse proxy** (`waf_proxy.h`) = الخط الأول قبل التطبيق | على Linux: 20 هجوم HTTP حقيقي = 403، GET/POST/JSON/chunked/1MB/20 متوازي = تمام، XFF المزوّر اتبدّل، سيرفر واقع = 502 |
| الـ node API على Windows بيفحص كل طلب بنفس الـ WAF | بيتبني؛ مش متجرّب تشغيل |
| تاب WebGuard (Windows) بيستخدم نفس الـ WAF للـ payload tester | بيتبني |
| الـ GUI بيفتح من غير تعليق (الفحوصات التقيلة اتنقلت لـ thread، قواعد الفايروول من الـ registry، نسخة عالقة بتتقفل) | Wine |
| الضبابية: GDI scaling في الـ manifest | **مش متأكد على شاشتك** (Windows 10 1809+) |
| الأيقونات: رسم vector بدل خط (بتشتغل على Linux/Wine) + نص UTF-8 صح (`â—` اختفت) | Wine screenshot |
| الثيم: Dark / OLED / Light / System + 8 ألوان accent على **البرنامج كله** | Wine screenshot |
| Gaming Mode: الحالة والأرقام حقيقية (مفيش ↓40% ثابتة) | Wine screenshot |
| Settings: الحماية الفورية (file watcher + AV) ومراقبة السلوك (parent/child, PowerShell, LOLBins, unsigned من Temp) متوصلين بالـ toggles؛ رسايل نجاح مزوّرة اتشالت (DNS flush, honeypot, VSS, lockdown, Supabase test) | يتبني فقط |
| Firewall Pro، CVE Intelligence (KEV+NVD → AI → winget → تحقق)، Self-Test، فحوصات فريق الـ AI الحقيقية، تحقق السلسلة HMAC للـ forensics | اختبارات portable + Wine |
| **نسخة Linux (terminal)**: selftest, posture+fix, conns, fw→nftables (اتطبّق في kernel الاختبار), cve (OSV+KEV+AI+apt+تحقق dpkg), ai, waf, ledger | اتجرّبت على Ubuntu 24.04 |

## 2) **لسه ما اتعملش** (طلبته وما خلصتش)
1. **GUI لـ Linux** — النسخة الحالية terminal فقط. (الـ exe بيشتغل تحت Wine بس ده مش native.)
2. **زر تشغيل الـ WAF proxy في GUI الـ Windows** — المحرك جاهز واتجرّب على Linux، بس مفيش زر في تاب WebGuard (استخدمه بـ `kaevex waf proxy` على Linux).
3. **الفحص الأولي الكامل عند أول تشغيل** + **عرض نتايج فحص الملفات في تاب Antivirus** — ما اتعملش. (الـ file watcher بيرفع alerts بس مفيش قايمة نتايج.)
4. **جدول الـ Agents في تاب "AI SOC Analyst" لسه بيانات تجريبية**: أسماء وCPU وذاكرة وuptime وعدّادات (Tasks 14 / Threats 69 / 7-7 online) **مش حقيقية**، وفيه نصوص كاذبة زي "Phantom: Exploit Builder" و"Nemesis: Nmap". **ما اتصلحش.**
   - اللي حقيقي: شات تاب **Full Team** (كل دور بياخد نتايج فحوصات حقيقية للجهاز: `/checks` و`/fix ID`)، وسطور "Live Activity" الجديدة (hunt حقيقي).
5. **Team / Invite**: مفيش طلب إيميل ولا ربط إحصائيات الجهاز الأساسي بالمدعو — ما اتعملش.
6. **Android**: ما لمستوش ولا اتبنى (مفيش Android SDK هنا). الـ API اتغيّر (PIN جديد، رد الـ AI، broadcast، cluster) فالـ app محتاج مراجعة.
7. **الـ Settings (≈186 إعداد)**: **حوالي 140 منهم بيتخزّنوا بس ومالهمش تأثير** (مفيش محرك وراهم). اللي متوصّل فعلاً: Real-Time, Behavior, Heuristic, Ransomware, Network scans, Theme/Accent, Lockdown, Firewall reset/DNS flush. لازم يتعمل: إما توصيل أو إخفاء الباقي.
8. **حاجات لسه شكلية/زخرفية**: الخريطة (heatmap) صورة ثابتة، عناوين SmartSandbox ("5-Layer AppContainer" — الحقيقي Sandboxie-Plus ولازم يتثبت)، أرقام "Defense Engines"، بعض نسب الـ KPI في تابات تانية.
9. **حجم الملفات**: الـ repo على GitHub مفيهوش بنارايز تقيلة (Sandboxie/Suricata/Zeek…). لو عندك ملفات إضافية على جهازك (GB)، **انسخ مجلد `src/`+`release/` من الـ zip فوق نسختك** مش تستبدل المجلد كله.
10. **اختبارات لم تتم**: NVD/CISA/OSV/مفتاح AI حقيقي (مفيش إنترنت هنا)، winget، تغيير فايروول Windows فعلي، الشاشة الحقيقية (DPI)، الربط بين جهازين.

## 3) المطلوب منك
- شغّل `Kaevex-Admin.bat` ثم Dashboard ← **System Status** (Self-Test) وابعتلي النتيجة.
- لو لسه مضبّب: Properties ← Compatibility ← Change high DPI ← Override: **System (Enhanced)**.
- حدد الأولوية للي فاضل (أقترح: 3 ثم 4 ثم 2 ثم Linux GUI).
