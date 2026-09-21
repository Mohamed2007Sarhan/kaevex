package com.kaevex.fireware.data.api

import com.kaevex.fireware.data.model.*
import retrofit2.Response
import retrofit2.http.*

interface KaevexApiService {

    @GET("api/v1/ping")
    suspend fun ping(): Response<PingResponse>

    @POST("api/v1/auth/pair")
    suspend fun pairDevice(@Body request: PairRequest): Response<PairResponse>

    @GET("api/v1/mobile/dashboard")
    suspend fun getDashboard(): Response<DashboardResponse>

    @POST("api/v1/firewall/lockdown")
    suspend fun toggleLockdown(@Body request: LockdownRequest): Response<ActionResponse>

    @GET("api/v1/threats")
    suspend fun getThreats(): Response<List<ThreatItem>>

    @POST("api/v1/threats/scan")
    suspend fun triggerScan(): Response<ActionResponse>

    @POST("api/v1/threats/mark-safe")
    suspend fun markSafe(@Body request: FilePathRequest): Response<ActionResponse>

    @POST("api/v1/threats/quarantine")
    suspend fun quarantine(@Body request: FilePathRequest): Response<ActionResponse>

    @GET("api/v1/network/connections")
    suspend fun getConnections(): Response<ConnectionsResponse>

    @GET("api/v1/boot-audit")
    suspend fun getBootAudit(): Response<BootAuditResponse>

    @GET("api/v1/hostguard/cves")
    suspend fun getCves(): Response<CveReportResponse>

    @POST("api/v1/cve/remediate")
    suspend fun remediateCve(@Body request: RemediateRequest): Response<RemediateResponse>

    @GET("api/v1/cluster/nodes")
    suspend fun getClusterNodes(): Response<ClusterResponse>

    @POST("api/v1/cluster/nodes")
    suspend fun addClusterNode(@Body request: AddServerRequest): Response<ActionResponse>

    @POST("api/v1/cluster/broadcast")
    suspend fun broadcastCluster(@Body request: BroadcastRequest): Response<BroadcastResponse>

    @POST("api/v1/ai/chat")
    suspend fun sendAiChat(@Body request: AiChatRequest): Response<AiChatResponse>

    @GET("api/v1/ai/config")
    suspend fun getAiConfig(): Response<AiConfigResponse>

    @POST("api/v1/ai/config")
    suspend fun updateAiConfig(@Body request: AiConfigRequest): Response<ActionResponse>

    @POST("api/v1/alerts/clear")
    suspend fun clearAlerts(): Response<ActionResponse>
}
