package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class DashboardResponse(
    @SerializedName("server") val server: ServerInfo = ServerInfo(),
    @SerializedName("resources") val resources: ResourceInfo = ResourceInfo(),
    @SerializedName("security") val security: SecurityInfo = SecurityInfo(),
    @SerializedName("traffic") val traffic: TrafficInfo = TrafficInfo(),
    @SerializedName("engines") val engines: List<EngineInfo> = emptyList(),
    @SerializedName("recent_alerts") val recentAlerts: List<AlertItem> = emptyList()
) {
    /**
     * Compute host integrity score (0 - 100%)
     * Starts at 100, deducted by active threats, unpatched items, or high system stress.
     */
    val integrityScore: Int
        get() {
            var score = 100
            if (security.totalThreats > 0) score -= (security.totalThreats * 15).coerceAtMost(40)
            if (security.firewallLocked) score += 5 // isolation bonus
            if (resources.cpuPercent > 85) score -= 10
            if (resources.ramPercent > 90) score -= 10
            val deadEngines = engines.count { it.status != "RUNNING" }
            score -= (deadEngines * 12)
            return score.coerceIn(0, 100)
        }
}

data class ServerInfo(
    @SerializedName("hostname") val hostname: String = "KAEVEX-HOST",
    @SerializedName("platform") val platform: String = "Windows 11 x64",
    @SerializedName("status") val status: String = "ONLINE_PROTECTED",
    @SerializedName("uptime_sec") val uptimeSec: Long = 0L
) {
    val uptimeFormatted: String
        get() {
            val hours = uptimeSec / 3600
            val minutes = (uptimeSec % 3600) / 60
            return "${hours}h ${minutes}m"
        }
}

data class ResourceInfo(
    @SerializedName("ram_percent") val ramPercent: Int = 0,
    @SerializedName("cpu_percent") val cpuPercent: Int = 0
)

data class SecurityInfo(
    @SerializedName("firewall_locked") val firewallLocked: Boolean = false,
    @SerializedName("total_threats") val totalThreats: Int = 0,
    @SerializedName("threats_quarantined") val threatsQuarantined: Int = 0,
    @SerializedName("threats_safe") val threatsSafe: Int = 0,
    @SerializedName("active_connections") val activeConnections: Int = 0,
    @SerializedName("waf_blocked") val wafBlocked: Int = 0,
    @SerializedName("waf_inspected") val wafInspected: Int = 0,
    @SerializedName("network_drops") val networkDrops: Int = 0
)

data class TrafficInfo(
    @SerializedName("inbound_pkts") val inboundPkts: Long = 0L,
    @SerializedName("outbound_pkts") val outboundPkts: Long = 0L,
    @SerializedName("sparkline") val sparkline: List<Int> = emptyList()
)

data class EngineInfo(
    @SerializedName("name") val name: String = "",
    @SerializedName("version") val version: String = "1.0.0",
    @SerializedName("status") val status: String = "RUNNING",
    @SerializedName("load") val load: Int = 0
)

data class AlertItem(
    @SerializedName("id") val id: Int = 0,
    @SerializedName("time") val time: String = "NOW",
    @SerializedName("sev") val severity: String = "INFO",
    @SerializedName("src") val source: String = "Engine",
    @SerializedName("msg") val message: String = ""
)
