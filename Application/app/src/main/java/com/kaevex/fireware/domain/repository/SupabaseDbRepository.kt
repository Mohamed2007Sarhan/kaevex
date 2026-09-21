package com.kaevex.fireware.domain.repository

import android.content.Context
import com.google.gson.Gson
import com.kaevex.fireware.data.local.KaevexLocalCache
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.model.*
import com.kaevex.fireware.data.supabase.*
import com.kaevex.fireware.domain.device.FullDeviceReport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SupabaseDbRepository(context: Context) {

    private val prefs = SecurePreferences(context)
    private val localCache = KaevexLocalCache(context)
    private val scope = CoroutineScope(Dispatchers.IO)
    private val gson = Gson()

    // --- Cluster Nodes Synchronization ---
    suspend fun syncClusterNodes(localServers: List<ServerNode>): List<ServerNode> = withContext(Dispatchers.IO) {
        try {
            val resp = SupabaseClient.api.getClusterNodes()
            if (resp.isSuccessful && !resp.body().isNullOrEmpty()) {
                val cloudNodes = resp.body()!!.map { entity ->
                    ServerNode(
                        id = entity.id?.toInt() ?: (entity.ip.hashCode() % 10000),
                        name = entity.name,
                        ip = entity.ip,
                        port = entity.port,
                        role = entity.role,
                        status = entity.status,
                        pingMs = entity.pingMs,
                        threats = entity.threats,
                        isLocked = entity.isLocked,
                        token = entity.token ?: "",
                        isActive = (entity.ip == prefs.activeServerIp && entity.port == prefs.activeServerPort)
                    )
                }
                prefs.saveServers(cloudNodes)
                return@withContext cloudNodes
            } else if (resp.isSuccessful && resp.body()?.isEmpty() == true) {
                // Initialize cloud table with default local servers
                localServers.forEach { node ->
                    saveClusterNode(node)
                }
            }
        } catch (_: Exception) {}
        localServers
    }

    fun saveClusterNode(node: ServerNode) {
        scope.launch {
            try {
                val entity = SupabaseNodeEntity(
                    id = if (node.id > 0) node.id.toLong() else null,
                    name = node.name,
                    ip = node.ip,
                    port = node.port,
                    role = node.role,
                    status = node.status,
                    pingMs = node.pingMs,
                    threats = node.threats,
                    isLocked = node.isLocked,
                    token = node.token,
                    userEmail = prefs.supabaseUserEmail
                )
                SupabaseClient.api.insertClusterNode(node = entity)
            } catch (_: Exception) {}
        }
    }

    fun deleteClusterNode(ip: String, port: Int) {
        scope.launch {
            try {
                SupabaseClient.api.deleteClusterNode(ipQuery = "eq.$ip", portQuery = "eq.$port")
            } catch (_: Exception) {}
        }
    }

    // --- Security Alerts Synchronization ---
    suspend fun fetchSecurityAlerts(): List<AlertItem>? = withContext(Dispatchers.IO) {
        try {
            val resp = SupabaseClient.api.getSecurityAlerts()
            if (resp.isSuccessful && resp.body() != null) {
                return@withContext resp.body()!!.map {
                    AlertItem(
                        id = it.id?.toInt() ?: 0,
                        time = it.time,
                        severity = it.severity,
                        source = it.source,
                        message = it.message
                    )
                }
            }
        } catch (_: Exception) {}
        null
    }

    fun saveSecurityAlerts(alerts: List<AlertItem>) {
        if (alerts.isEmpty()) return
        scope.launch {
            try {
                val entities = alerts.map {
                    SupabaseAlertEntity(
                        time = it.time,
                        severity = it.severity,
                        source = it.source,
                        message = it.message,
                        userEmail = prefs.supabaseUserEmail
                    )
                }
                SupabaseClient.api.insertSecurityAlerts(alerts = entities)
            } catch (_: Exception) {}
        }
    }

    fun clearSecurityAlerts() {
        scope.launch {
            try {
                SupabaseClient.api.clearSecurityAlerts()
            } catch (_: Exception) {}
        }
    }

    // --- AI Chat History Synchronization ---
    suspend fun fetchAiChatHistory(): List<ChatMessage> = withContext(Dispatchers.IO) {
        try {
            val resp = SupabaseClient.api.getAiChatMessages()
            if (resp.isSuccessful && !resp.body().isNullOrEmpty()) {
                return@withContext resp.body()!!.map { entity ->
                    ChatMessage(
                        id = entity.messageUuid,
                        sender = if (entity.sender == "USER") MessageSender.USER else MessageSender.SOC_AGENT,
                        text = entity.text,
                        timestamp = entity.timestamp,
                        team = entity.team,
                        action = if (!entity.actionType.isNullOrBlank()) {
                            AiAction(
                                actionType = entity.actionType,
                                label = entity.actionLabel ?: entity.actionType,
                                target = entity.actionTarget ?: "",
                                dangerLevel = "HIGH"
                            )
                        } else null,
                        executionResult = entity.executionResult
                    )
                }
            }
        } catch (_: Exception) {}
        emptyList()
    }

    fun saveAiChatMessage(msg: ChatMessage) {
        scope.launch {
            try {
                val entity = SupabaseChatMessageEntity(
                    messageUuid = msg.id,
                    sender = if (msg.sender == MessageSender.USER) "USER" else "SOC_AGENT",
                    text = msg.text,
                    team = msg.team,
                    timestamp = msg.timestamp,
                    actionType = msg.action?.actionType,
                    actionLabel = msg.action?.label,
                    actionTarget = msg.action?.target,
                    executionResult = msg.executionResult,
                    userEmail = prefs.supabaseUserEmail
                )
                SupabaseClient.api.insertAiChatMessage(message = entity)
            } catch (_: Exception) {}
        }
    }

    fun updateAiChatActionExecution(messageUuid: String, result: String) {
        scope.launch {
            try {
                SupabaseClient.api.updateAiChatAction(
                    uuidQuery = "eq.$messageUuid",
                    body = mapOf("execution_result" to result)
                )
            } catch (_: Exception) {}
        }
    }

    // --- Mobile Device Telemetry Sync ---
    fun saveDeviceTelemetry(report: FullDeviceReport) {
        scope.launch {
            try {
                val hw = report.hardware
                val sec = report.security
                val entity = SupabaseDeviceTelemetryEntity(
                    userEmail = prefs.supabaseUserEmail,
                    deviceModel = "${hw.manufacturer} ${hw.model}",
                    batteryPct = hw.batteryPercent,
                    isCharging = hw.isCharging,
                    availableRamMb = hw.availableRamMb,
                    totalRamMb = hw.totalRamMb,
                    freeStorageGb = hw.freeStorageGb,
                    localIp = hw.localIpAddress,
                    connectionType = hw.connectionType,
                    isRooted = sec.isRooted,
                    isAdbActive = sec.isAdbEnabled,
                    integrityScore = sec.integrityScore,
                    verdict = sec.securityVerdict
                )
                SupabaseClient.api.insertDeviceTelemetry(telemetry = entity)
            } catch (_: Exception) {}
        }
    }

    // --- Bootkit Forensic Reports ---
    fun saveBootAuditReport(audit: BootAuditResponse) {
        scope.launch {
            try {
                val entity = SupabaseBootAuditEntity(
                    status = audit.status,
                    secureBootEnabled = audit.uefi.secureBootEnabled,
                    testSigningDisabled = audit.bcd.testSigningDisabled,
                    mbrSignatureValid = audit.bootSector.mbrSignatureValid,
                    coreBinariesVerified = audit.coreBinaries.count { it.catRootStatus == "CATROOT2_MATCH" },
                    auditJson = gson.toJson(audit),
                    userEmail = prefs.supabaseUserEmail
                )
                SupabaseClient.api.insertBootAudit(audit = entity)
            } catch (_: Exception) {}
        }
    }

    // --- CVE Records & Remediation Sync ---
    fun saveCveRemediation(cveId: String) {
        scope.launch {
            try {
                SupabaseClient.api.updateCveRemediation(
                    cveIdQuery = "eq.$cveId",
                    body = mapOf(
                        "is_patched" to true,
                        "remediated_at" to java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US).format(java.util.Date())
                    )
                )
            } catch (_: Exception) {}
        }
    }

    // --- Operator Settings Sync ---
    fun saveOperatorSettings() {
        scope.launch {
            val email = prefs.supabaseUserEmail ?: return@launch
            try {
                val entity = SupabaseSettingsEntity(
                    userEmail = email,
                    biometricsEnabled = prefs.biometricsEnabled,
                    refreshIntervalSec = prefs.refreshIntervalSec,
                    requestTimeoutSec = prefs.requestTimeoutSec,
                    togetherApiKey = prefs.togetherApiKey,
                    aiModel = prefs.aiModel
                )
                SupabaseClient.api.upsertOperatorSettings(settings = entity)
            } catch (_: Exception) {}
        }
    }
}
