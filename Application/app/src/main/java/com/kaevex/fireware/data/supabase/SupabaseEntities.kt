package com.kaevex.fireware.data.supabase

import com.google.gson.annotations.SerializedName

data class SupabaseNodeEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("name") val name: String,
    @SerializedName("ip") val ip: String,
    @SerializedName("port") val port: Int,
    @SerializedName("role") val role: String,
    @SerializedName("status") val status: String,
    @SerializedName("ping_ms") val pingMs: Int,
    @SerializedName("threats") val threats: Int,
    @SerializedName("is_locked") val isLocked: Boolean,
    @SerializedName("token") val token: String? = null,
    @SerializedName("user_email") val userEmail: String? = null
)

data class SupabaseAlertEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("time") val time: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("source") val source: String,
    @SerializedName("message") val message: String,
    @SerializedName("is_resolved") val isResolved: Boolean = false,
    @SerializedName("user_email") val userEmail: String? = null
)

data class SupabaseChatMessageEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("message_uuid") val messageUuid: String,
    @SerializedName("sender") val sender: String,
    @SerializedName("text") val text: String,
    @SerializedName("team") val team: String,
    @SerializedName("timestamp") val timestamp: String,
    @SerializedName("action_type") val actionType: String? = null,
    @SerializedName("action_label") val actionLabel: String? = null,
    @SerializedName("action_target") val actionTarget: String? = null,
    @SerializedName("execution_result") val executionResult: String? = null,
    @SerializedName("user_email") val userEmail: String? = null
)

data class SupabaseDeviceTelemetryEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("user_email") val userEmail: String? = null,
    @SerializedName("device_model") val deviceModel: String,
    @SerializedName("battery_pct") val batteryPct: Int,
    @SerializedName("is_charging") val isCharging: Boolean,
    @SerializedName("available_ram_mb") val availableRamMb: Long,
    @SerializedName("total_ram_mb") val totalRamMb: Long,
    @SerializedName("free_storage_gb") val freeStorageGb: Double,
    @SerializedName("local_ip") val localIp: String,
    @SerializedName("connection_type") val connectionType: String,
    @SerializedName("is_rooted") val isRooted: Boolean,
    @SerializedName("is_adb_active") val isAdbActive: Boolean,
    @SerializedName("integrity_score") val integrityScore: Int,
    @SerializedName("verdict") val verdict: String
)

data class SupabaseCveEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("cve_id") val cveId: String,
    @SerializedName("title") val title: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("cvss") val cvss: Double,
    @SerializedName("affected_software") val affectedSoftware: String,
    @SerializedName("is_patched") val isPatched: Boolean,
    @SerializedName("can_auto_remediate") val canAutoRemediate: Boolean,
    @SerializedName("remediated_at") val remediatedAt: String? = null
)

data class SupabaseBootAuditEntity(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("status") val status: String,
    @SerializedName("secure_boot_enabled") val secureBootEnabled: Boolean,
    @SerializedName("test_signing_disabled") val testSigningDisabled: Boolean,
    @SerializedName("mbr_signature_valid") val mbrSignatureValid: Boolean,
    @SerializedName("core_binaries_verified") val coreBinariesVerified: Int,
    @SerializedName("audit_json") val auditJson: String,
    @SerializedName("user_email") val userEmail: String? = null
)

data class SupabaseSettingsEntity(
    @SerializedName("user_email") val userEmail: String,
    @SerializedName("biometrics_enabled") val biometricsEnabled: Boolean,
    @SerializedName("refresh_interval_sec") val refreshIntervalSec: Int,
    @SerializedName("request_timeout_sec") val requestTimeoutSec: Long,
    @SerializedName("together_api_key") val togetherApiKey: String? = null,
    @SerializedName("ai_model") val aiModel: String? = null
)
