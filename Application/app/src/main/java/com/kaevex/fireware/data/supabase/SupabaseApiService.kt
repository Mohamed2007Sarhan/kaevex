package com.kaevex.fireware.data.supabase

import retrofit2.Response
import retrofit2.http.*

interface SupabaseApiService {

    // --- Authentication ---
    @POST("auth/v1/signup")
    suspend fun signUp(
        @Body request: SupabaseSignUpRequest
    ): Response<SupabaseAuthResponse>

    @POST("auth/v1/token?grant_type=password")
    suspend fun signIn(
        @Body request: SupabaseSignInRequest
    ): Response<SupabaseAuthResponse>

    @POST("auth/v1/logout")
    suspend fun logout(): Response<Unit>

    // --- Activity Telemetry Logs ---
    @POST("rest/v1/mobile_activity_logs")
    suspend fun insertActivityLog(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body log: MobileActivityLog
    ): Response<Unit>

    @GET("rest/v1/mobile_activity_logs")
    suspend fun getActivityLogs(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.desc",
        @Query("limit") limit: Int = 50
    ): Response<List<MobileActivityLog>>

    // --- Cluster Nodes Table ---
    @GET("rest/v1/cluster_nodes")
    suspend fun getClusterNodes(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.asc"
    ): Response<List<SupabaseNodeEntity>>

    @POST("rest/v1/cluster_nodes")
    suspend fun insertClusterNode(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body node: SupabaseNodeEntity
    ): Response<Unit>

    @DELETE("rest/v1/cluster_nodes")
    suspend fun deleteClusterNode(
        @Query("ip") ipQuery: String,
        @Query("port") portQuery: String
    ): Response<Unit>

    // --- Security Alerts Table ---
    @GET("rest/v1/security_alerts")
    suspend fun getSecurityAlerts(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.desc",
        @Query("limit") limit: Int = 50
    ): Response<List<SupabaseAlertEntity>>

    @POST("rest/v1/security_alerts")
    suspend fun insertSecurityAlerts(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body alerts: List<SupabaseAlertEntity>
    ): Response<Unit>

    @DELETE("rest/v1/security_alerts")
    suspend fun clearSecurityAlerts(
        @Query("id") idQuery: String = "neq.0"
    ): Response<Unit>

    // --- AI Chat Messages Table ---
    @GET("rest/v1/ai_chat_messages")
    suspend fun getAiChatMessages(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.asc",
        @Query("limit") limit: Int = 100
    ): Response<List<SupabaseChatMessageEntity>>

    @POST("rest/v1/ai_chat_messages")
    suspend fun insertAiChatMessage(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body message: SupabaseChatMessageEntity
    ): Response<Unit>

    @PATCH("rest/v1/ai_chat_messages")
    suspend fun updateAiChatAction(
        @Query("message_uuid") uuidQuery: String,
        @Body body: Map<String, String>
    ): Response<Unit>

    // --- Mobile Device Telemetry Table ---
    @POST("rest/v1/device_telemetry")
    suspend fun insertDeviceTelemetry(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body telemetry: SupabaseDeviceTelemetryEntity
    ): Response<Unit>

    @GET("rest/v1/device_telemetry")
    suspend fun getLatestDeviceTelemetry(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.desc",
        @Query("limit") limit: Int = 1
    ): Response<List<SupabaseDeviceTelemetryEntity>>

    // --- CVE Records Table ---
    @GET("rest/v1/cve_records")
    suspend fun getCveRecords(
        @Query("select") select: String = "*"
    ): Response<List<SupabaseCveEntity>>

    @POST("rest/v1/cve_records")
    suspend fun insertCveRecords(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body records: List<SupabaseCveEntity>
    ): Response<Unit>

    @PATCH("rest/v1/cve_records")
    suspend fun updateCveRemediation(
        @Query("cve_id") cveIdQuery: String,
        @Body body: Map<String, Any>
    ): Response<Unit>

    // --- Bootkit Forensics Table ---
    @GET("rest/v1/boot_audit_reports")
    suspend fun getLatestBootAudit(
        @Query("select") select: String = "*",
        @Query("order") order: String = "id.desc",
        @Query("limit") limit: Int = 1
    ): Response<List<SupabaseBootAuditEntity>>

    @POST("rest/v1/boot_audit_reports")
    suspend fun insertBootAudit(
        @Header("Prefer") prefer: String = "return=minimal",
        @Body audit: SupabaseBootAuditEntity
    ): Response<Unit>

    // --- Operator Settings Table ---
    @GET("rest/v1/operator_settings")
    suspend fun getOperatorSettings(
        @Query("user_email") emailQuery: String
    ): Response<List<SupabaseSettingsEntity>>

    @POST("rest/v1/operator_settings")
    suspend fun upsertOperatorSettings(
        @Header("Prefer") prefer: String = "resolution=merge-duplicates",
        @Body settings: SupabaseSettingsEntity
    ): Response<Unit>
}
