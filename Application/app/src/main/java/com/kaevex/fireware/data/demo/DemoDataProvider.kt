package com.kaevex.fireware.data.demo

import com.kaevex.fireware.data.model.*
import kotlin.random.Random

object DemoDataProvider {

    fun getDemoDashboard(firewallLocked: Boolean = false): DashboardResponse {
        val cpuJitter = (14 + Random.nextInt(-3, 6)).coerceIn(8, 95)
        val ramJitter = (68 + Random.nextInt(-2, 4)).coerceIn(40, 95)

        val sparkline = mutableListOf(145, 210, 175, 290, 240, 350, 310, 280, 390, 340, 420)
        sparkline.add((320 + Random.nextInt(-30, 50)).coerceIn(100, 600))
        while (sparkline.size > 12) sparkline.removeAt(0)

        return DashboardResponse(
            server = ServerInfo(
                hostname = "MOHAMED-PC",
                platform = "Windows 11 Pro x64 (24H2)",
                status = if (firewallLocked) "ISOLATED_LOCKDOWN" else "ONLINE_PROTECTED",
                uptimeSec = 48293L
            ),
            resources = ResourceInfo(
                ramPercent = ramJitter,
                cpuPercent = cpuJitter
            ),
            security = SecurityInfo(
                firewallLocked = firewallLocked,
                totalThreats = 0,
                threatsQuarantined = 4,
                threatsSafe = 12,
                activeConnections = 76,
                wafBlocked = 28,
                wafInspected = 1420,
                networkDrops = 6
            ),
            traffic = TrafficInfo(
                inboundPkts = 6410130L,
                outboundPkts = 4116336L,
                sparkline = sparkline
            ),
            engines = listOf(
                EngineInfo("Antivirus Core (WinAPI/CryptoAPI)", "3.0.0", "RUNNING", 14),
                EngineInfo("NetGuard Network Monitor", "2.1.0", "RUNNING", 22),
                EngineInfo("WebGuard Inline WAF", "3.0.0", "RUNNING", 11),
                EngineInfo("Adaptive Firewall Controller", "1.2.0", "RUNNING", 8),
                EngineInfo("RansomShield Canary Sentinel", "2.0.0", "RUNNING", 6),
                EngineInfo("SmartSandbox AppContainer", "2.0.0", "RUNNING", 4),
                EngineInfo("Autonomous CVE Patch Agent", "3.0.0", "RUNNING", 12),
                EngineInfo("App Discovery & Identity Hub", "1.1.0", "RUNNING", 7)
            ),
            recentAlerts = listOf(
                AlertItem(101, "NOW", "CRITICAL", "WebGuard WAF", "Blocked SQLi payload [UNION SELECT] from 185.220.101.5"),
                AlertItem(102, "T-2m", "HIGH", "NetGuard", "Proactive drop on port scan probe TCP/445 from 45.154.255.88"),
                AlertItem(103, "T-7m", "INFO", "Antivirus Core", "SHA-256 integrity clean on svchost.exe memory space"),
                AlertItem(104, "T-14m", "LOW", "RansomShield", "Canary decoys intact across 8 system volumes"),
                AlertItem(105, "T-22m", "INFO", "CVE Agent", "Continuous registry watcher verified zero unpatched zero-days")
            )
        )
    }

    fun getDemoBootAudit(): BootAuditResponse {
        return BootAuditResponse(
            status = "SUCCESS",
            auditTimestamp = "2026-09-21 03:30:12 UTC",
            overallIntegrity = "PASSED",
            uefi = UefiInfo(
                secureBootEnabled = true,
                nvramState = "ACTIVE_LOCKED",
                setupMode = false,
                vendor = "American Megatrends (AMI UEFI v2.20)",
                details = "Hardware Root-of-Trust and TPM 2.0 PCR-7 Platform Auth Enforced"
            ),
            bcd = BcdInfo(
                testSigningDisabled = true,
                driverSigningEnforced = true,
                noIntegrityChecks = false,
                hypervisorLaunchType = "AUTO (Hyper-V Guard Active)",
                statusText = "Code Integrity Enforced: Unsigned drivers strictly rejected"
            ),
            bootSector = BootSectorInfo(
                mbrSignatureValid = true,
                mbrMagic = "0x55AA",
                bootmgfwValid = true,
                authenticodeVerified = true,
                certSubject = "Microsoft Windows Production PCA 2011",
                hashSha256 = "8A4C2E60F9D8312BA41940E8117760A8DE249910C24B",
                details = "ESP bootmgfw.efi Authenticode signature & Sector 0 Magic 0x55AA Verified"
            ),
            coreBinaries = listOf(
                CoreBinaryInfo("ntoskrnl.exe", "C:\\Windows\\System32\\ntoskrnl.exe", "VERIFIED_VALID", "CATROOT2_MATCH", "9A2F8B", false),
                CoreBinaryInfo("hal.dll", "C:\\Windows\\System32\\hal.dll", "VERIFIED_VALID", "CATROOT2_MATCH", "710C3E", false),
                CoreBinaryInfo("kernel32.dll", "C:\\Windows\\System32\\kernel32.dll", "VERIFIED_VALID", "CATROOT2_MATCH", "42B9A1", false),
                CoreBinaryInfo("user32.dll", "C:\\Windows\\System32\\user32.dll", "VERIFIED_VALID", "CATROOT2_MATCH", "88DF02", false),
                CoreBinaryInfo("csrss.exe", "C:\\Windows\\System32\\csrss.exe", "VERIFIED_VALID", "CATROOT2_MATCH", "19FA66", false),
                CoreBinaryInfo("winlogon.exe", "C:\\Windows\\System32\\winlogon.exe", "VERIFIED_VALID", "CATROOT2_MATCH", "53EE19", false),
                CoreBinaryInfo("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "VERIFIED_VALID", "CATROOT2_MATCH", "64D120", false),
                CoreBinaryInfo("lsass.exe", "C:\\Windows\\System32\\lsass.exe", "VERIFIED_VALID", "CATROOT2_MATCH", "32AA81", false)
            ),
            scm = ScmInfo(
                totalServicesAudited = 296,
                rogueMasqueraders = 0,
                kernelDriversInRam = 184,
                unsignedDriversInRam = 0,
                details = "296 System services audited. Zero rogue masqueraders. 184 signed drivers active."
            )
        )
    }

    fun getDemoCveReport(): CveReportResponse {
        return CveReportResponse(
            status = "SUCCESS",
            compliance = ComplianceStatus(
                cisBenchmarkScore = 94,
                statusLabel = "CIS Benchmark: 94% Compliant",
                nistScore = 91,
                totalAuditedRules = 120,
                passedRules = 113,
                failedRules = 7
            ),
            patchedCves = listOf(
                CveItem(
                    cveId = "CVE-2024-38077",
                    softwareName = "Windows Remote Desktop Licensing",
                    installedVersion = "10.0.26100.1742",
                    patchedVersion = "10.0.26100.1882",
                    severity = "CRITICAL",
                    cvssScore = 9.8,
                    title = "Windows Remote Desktop Licensing Service RCE Vulnerability",
                    mitigationDate = "2026-08-14",
                    patchStatus = "KB5041585_APPLIED",
                    canAutoRemediate = false
                ),
                CveItem(
                    cveId = "CVE-2024-30078",
                    softwareName = "Windows Wi-Fi Driver Stack",
                    installedVersion = "10.0.26100.1150",
                    patchedVersion = "10.0.26100.1591",
                    severity = "CRITICAL",
                    cvssScore = 8.8,
                    title = "Windows Wi-Fi Driver Remote Code Execution Vulnerability",
                    mitigationDate = "2026-08-18",
                    patchStatus = "WINGET_PATCHED",
                    canAutoRemediate = false
                ),
                CveItem(
                    cveId = "CVE-2024-21307",
                    softwareName = "Hyper-V Virtualization Core",
                    installedVersion = "Build 26100",
                    patchedVersion = "Build 26100.1457",
                    severity = "HIGH",
                    cvssScore = 7.7,
                    title = "Hyper-V Remote Denial of Service Mitigation",
                    mitigationDate = "2026-08-25",
                    patchStatus = "HOTFIX_ENFORCED",
                    canAutoRemediate = false
                ),
                CveItem(
                    cveId = "CVE-2024-4577",
                    softwareName = "PHP CGI Runtime",
                    installedVersion = "8.2.14",
                    patchedVersion = "8.2.20",
                    severity = "CRITICAL",
                    cvssScore = 9.8,
                    title = "PHP CGI Argument Injection RCE",
                    mitigationDate = "2026-09-02",
                    patchStatus = "WINGET_PATCHED",
                    canAutoRemediate = false
                )
            ),
            activeRisks = listOf(
                CveItem(
                    cveId = "CVE-2025-1192",
                    softwareName = "7-Zip Compression Utility",
                    installedVersion = "23.01",
                    patchedVersion = "24.08",
                    severity = "HIGH",
                    cvssScore = 7.8,
                    title = "Unquoted Search Path Arbitrary Code Execution",
                    mitigationDate = "PENDING",
                    patchStatus = "PENDING_UPDATE",
                    canAutoRemediate = true,
                    remediationCommand = "winget upgrade 7zip.7zip --silent"
                ),
                CveItem(
                    cveId = "CVE-2024-24576",
                    softwareName = "Git for Windows (Bat/Cmd Wrapper)",
                    installedVersion = "2.44.0",
                    patchedVersion = "2.45.1",
                    severity = "HIGH",
                    cvssScore = 8.1,
                    title = "Windows Batch File Argument Injection",
                    mitigationDate = "PENDING",
                    patchStatus = "PENDING_UPDATE",
                    canAutoRemediate = true,
                    remediationCommand = "winget upgrade Git.Git --silent"
                ),
                CveItem(
                    cveId = "CVE-2024-4367",
                    softwareName = "Mozilla PDF.js Font Engine",
                    installedVersion = "3.11.174",
                    patchedVersion = "4.2.67",
                    severity = "MEDIUM",
                    cvssScore = 6.5,
                    title = "Arbitrary JavaScript Execution in PDF Preview",
                    mitigationDate = "PENDING",
                    patchStatus = "PENDING_UPDATE",
                    canAutoRemediate = true,
                    remediationCommand = "npm update pdfjs-dist"
                )
            )
        )
    }

    fun parseAiChatResponse(prompt: String, team: String): AiChatResponse {
        val lower = prompt.lowercase()
        val isArabic = prompt.any { it in '\u0600'..'\u06FF' }

        return when {
            lower.contains("lockdown") || lower.contains("isolate") || lower.contains("اعزل") || lower.contains("اغلاق") -> {
                val ipTarget = extractIp(prompt) ?: "192.168.1.50"
                AiChatResponse(
                    status = "success",
                    provider = "Together AI (DeepSeek-V4-Pro)",
                    model = "deepseek-ai/DeepSeek-V4-Pro-0813",
                    team = team,
                    prompt = prompt,
                    reply = if (isArabic) {
                        "تم تحليل طلبك لعزل الهدف [$ipTarget]. تنشيط وضع إغلاق الطوارئ سيقوم بقطع كافة الاتصالات الشبكية فوراً عبر Windows Filtering Platform باستثناء جلسة تحكم الموبايل المشفرة."
                    } else {
                        "Emergency isolation command evaluated for [$ipTarget]. Engaging network lockdown will immediately sever all unauthorized TCP/UDP sockets via Windows Filtering Platform while preserving our secure mobile control session."
                    },
                    recommendations = listOf(
                        "Verify critical telemetry before confirmation",
                        "Audit inbound dropped packets post-lockdown"
                    ),
                    action = AiAction(
                        actionType = "LOCKDOWN",
                        label = if (isArabic) "تأكيد: عزل $ipTarget فوراً" else "CONFIRM: Isolate $ipTarget",
                        target = ipTarget,
                        dangerLevel = "HIGH"
                    )
                )
            }

            lower.contains("boot") || lower.contains("uefi") || lower.contains("mbr") || lower.contains("بوت") -> {
                AiChatResponse(
                    status = "success",
                    provider = "Together AI (DeepSeek-V4-Pro)",
                    model = "deepseek-ai/DeepSeek-V4-Pro-0813",
                    team = team,
                    prompt = prompt,
                    reply = if (isArabic) {
                        "تم فحص توقيعات قطاع الإقلاع UEFI و MBR. جميع ملفات النواة الثمانية (ntoskrnl.exe وغيرها) متطابقة بنسبة 100% مع كتالوج مايكروسوفت الرسمي ولا توجد أي مشغلات غير موقعة في الذاكرة."
                    } else {
                        "Low-level UEFI Bootkit & Kernel audit completed. All 8 core Windows binaries match CatRoot Authenticode signatures with Sector 0 magic (0x55AA) verified intact."
                    },
                    recommendations = listOf(
                        "Secure Boot NVRAM state remains locked",
                        "Driver test-signing is strictly prohibited"
                    ),
                    action = AiAction(
                        actionType = "BOOT_AUDIT",
                        label = if (isArabic) "تأكيد: إعادة تدقيق البوت كيت" else "CONFIRM: Run Bootkit Audit",
                        target = "UEFI_NVRAM",
                        dangerLevel = "LOW"
                    )
                )
            }

            lower.contains("scan") || lower.contains("افحص") || lower.contains("فحص") -> {
                AiChatResponse(
                    status = "success",
                    provider = "Together AI (DeepSeek-V4-Pro)",
                    model = "deepseek-ai/DeepSeek-V4-Pro-0813",
                    team = team,
                    prompt = prompt,
                    reply = if (isArabic) {
                        "جاهز لإطلاق فحص معمق شامل لكافة العمليات الحية وملفات النظام الحساسة باستخدام محركات التجزئة الثنائية CryptoAPI وShannon Entropy."
                    } else {
                        "Ready to dispatch a deep system-wide antivirus and memory inspection using CryptoAPI dual-hash matching and Shannon entropy heuristics."
                    },
                    recommendations = listOf(
                        "Scans run asynchronously without UI latency",
                        "Results stream to Alert Stream & Dashboard"
                    ),
                    action = AiAction(
                        actionType = "SCAN",
                        label = if (isArabic) "تأكيد: إطلاق فحص شامل للنظام" else "CONFIRM: Launch Deep Scan",
                        target = "SYSTEM_ROOT",
                        dangerLevel = "MEDIUM"
                    )
                )
            }

            lower.contains("ban") || lower.contains("block") || lower.contains("احظر") || lower.contains("حظر") -> {
                val ipTarget = extractIp(prompt) ?: "185.220.101.5"
                AiChatResponse(
                    status = "success",
                    provider = "Together AI (DeepSeek-V4-Pro)",
                    model = "deepseek-ai/DeepSeek-V4-Pro-0813",
                    team = team,
                    prompt = prompt,
                    reply = if (isArabic) {
                        "تم تحديد العنوان المشبوه [$ipTarget]. بالضغط على البطاقة أدناه سيتم حقن قاعدة حظر فورية في جدار حماية ويندوز وWebGuard WAF."
                    } else {
                        "Identified threat IP [$ipTarget]. Clicking the confirmation card below injects an immediate firewall block rule in Windows Netsh & WebGuard."
                    },
                    recommendations = listOf(
                        "Check connection telemetry for concurrent sockets",
                        "Propagate block rule across all cluster nodes"
                    ),
                    action = AiAction(
                        actionType = "BAN_IP",
                        label = if (isArabic) "تأكيد: حظر $ipTarget" else "CONFIRM: Ban $ipTarget",
                        target = ipTarget,
                        dangerLevel = "HIGH"
                    )
                )
            }

            else -> {
                AiChatResponse(
                    status = "success",
                    provider = "Together AI (DeepSeek-V4-Pro)",
                    model = "deepseek-ai/DeepSeek-V4-Pro-0813",
                    team = team,
                    prompt = prompt,
                    reply = if (isArabic) {
                        "مرحباً بك في مركز قيادة السوك السيبراني [فريق $team]. المنظومة الدفاعية تعمل بكامل طاقتها، جدار الحماية التكيفي ومحرك WAF يراقبان الحزم لحظياً. يمكنك سؤالي عن تحليل التهديدات، فحص البوت كيت، أو تنفيذ إغلاق الطوارئ."
                    } else {
                        "Kaevex SOC Analyst [Team $team] online. All 8 defense engines, inline WAF, and low-level kernel integrity guardians are operating at 100% efficiency. Ask me to isolate nodes, inspect bootkits, or remediate CVEs."
                    },
                    recommendations = listOf(
                        "CIS Benchmark: 94% Compliant",
                        "Zero unpatched critical zero-days active"
                    ),
                    action = null
                )
            }
        }
    }

    private fun extractIp(text: String): String? {
        val regex = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""")
        return regex.find(text)?.value
    }
}
