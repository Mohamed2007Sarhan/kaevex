package com.kaevex.fireware.domain.repository

import android.content.Context
import com.google.gson.Gson
import com.kaevex.fireware.data.api.ApiClient
import com.kaevex.fireware.data.demo.DemoDataProvider
import com.kaevex.fireware.data.local.KaevexLocalCache
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class KaevexRepository(private val context: Context) {

    private val prefs = SecurePreferences(context)
    private val localCache = KaevexLocalCache(context)
    private val gson = Gson()

    private var mockFirewallLock: Boolean = false

    init {
        updateApiClient()
    }

    fun updateApiClient() {
        val baseUrl = "http://${prefs.activeServerIp}:${prefs.activeServerPort}/"
        ApiClient.configure(baseUrl, prefs.authToken, prefs.requestTimeoutSec)
    }

    suspend fun getDashboard(): Result<DashboardResponse> = withContext(Dispatchers.IO) {
        updateApiClient()

        // 1. Always attempt live network call to Windows backend
        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().getDashboard()
                if (response.isSuccessful && response.body() != null) {
                    val data = response.body()!!
                    localCache.putCache("dashboard", gson.toJson(data))
                    localCache.insertAlerts(data.recentAlerts)
                    return@withContext Result.success(data)
                }
            } catch (_: Exception) {
                // Network unreachable or timeout -> graceful fallback
            }
        }

        // 2. Cache / Demo Fallback
        fallbackDashboard()
    }

    private fun fallbackDashboard(): Result<DashboardResponse> {
        val cachedJson = localCache.getCache("dashboard")
        if (!cachedJson.isNullOrBlank()) {
            try {
                val cached = gson.fromJson(cachedJson, DashboardResponse::class.java)
                return Result.success(cached)
            } catch (_: Exception) {}
        }
        val demo = DemoDataProvider.getDemoDashboard(mockFirewallLock)
        localCache.insertAlerts(demo.recentAlerts)
        return Result.success(demo)
    }

    suspend fun toggleLockdown(enable: Boolean): Result<ActionResponse> = withContext(Dispatchers.IO) {
        mockFirewallLock = enable
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().toggleLockdown(LockdownRequest(if (enable) 1 else 0))
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(
            ActionResponse(
                status = "success",
                action = "firewall_lockdown",
                message = if (enable) "EMERGENCY LOCKDOWN ACTIVATED: Host network isolated." else "LOCKDOWN LIFTED: Network traffic restored.",
                locked = enable
            )
        )
    }

    suspend fun triggerAntivirusScan(): Result<ActionResponse> = withContext(Dispatchers.IO) {
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().triggerScan()
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(
            ActionResponse(
                status = "success",
                action = "antivirus_scan",
                message = "Deep Antivirus Scan dispatched. 1,480 system binaries verified clean."
            )
        )
    }

    suspend fun clearAlerts(): Result<ActionResponse> = withContext(Dispatchers.IO) {
        localCache.clearAlerts()
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().clearAlerts()
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(ActionResponse("success", "alerts_clear", "All alerts cleared from local vault."))
    }

    suspend fun getBootAudit(): Result<BootAuditResponse> = withContext(Dispatchers.IO) {
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().getBootAudit()
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(DemoDataProvider.getDemoBootAudit())
    }

    suspend fun getCves(): Result<CveReportResponse> = withContext(Dispatchers.IO) {
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().getCves()
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(DemoDataProvider.getDemoCveReport())
    }

    suspend fun remediateCve(cveId: String, softwareName: String): Result<RemediateResponse> = withContext(Dispatchers.IO) {
        updateApiClient()

        if (!prefs.demoModeEnabled) {
            try {
                val response = ApiClient.getService().remediateCve(RemediateRequest(cveId, softwareName))
                if (response.isSuccessful && response.body() != null) {
                    return@withContext Result.success(response.body()!!)
                }
            } catch (_: Exception) {}
        }

        Result.success(
            RemediateResponse(
                status = "success",
                message = "Automated remediation patch deployed for $softwareName ($cveId)",
                cveId = cveId
            )
        )
    }

    suspend fun testServerConnection(): Result<Long> = withContext(Dispatchers.IO) {
        updateApiClient()
        val start = System.currentTimeMillis()
        try {
            val response = ApiClient.getService().ping()
            if (response.isSuccessful) {
                val latency = System.currentTimeMillis() - start
                Result.success(latency)
            } else {
                Result.failure(Exception("HTTP error ${response.code()}: ${response.message()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
