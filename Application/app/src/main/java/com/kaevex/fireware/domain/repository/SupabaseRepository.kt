package com.kaevex.fireware.domain.repository

import android.content.Context
import android.os.Build
import com.google.gson.Gson
import com.kaevex.fireware.data.local.KaevexLocalCache
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.supabase.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

class SupabaseRepository(context: Context) {

    private val prefs = SecurePreferences(context)
    private val localCache = KaevexLocalCache(context)
    private val scope = CoroutineScope(Dispatchers.IO)
    private val gson = Gson()

    val deviceInfo: String by lazy {
        "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL} (Android ${Build.VERSION.RELEASE}, API ${Build.VERSION.SDK_INT})"
    }

    init {
        // Initialize token if already present in secure prefs
        if (!prefs.supabaseAccessToken.isNullOrBlank()) {
            SupabaseClient.setAuthToken(prefs.supabaseAccessToken)
        }
    }

    suspend fun signIn(email: String, pass: String): Result<SupabaseAuthResponse> {
        return try {
            val response = SupabaseClient.api.signIn(
                SupabaseSignInRequest(email = email.trim(), password = pass)
            )

            if (response.isSuccessful && response.body() != null) {
                val authRes = response.body()!!
                authRes.accessToken?.let { token ->
                    prefs.supabaseAccessToken = token
                    SupabaseClient.setAuthToken(token)
                }
                authRes.refreshToken?.let { prefs.supabaseRefreshToken = it }
                authRes.user?.let { user ->
                    prefs.supabaseUserEmail = user.email ?: email
                    prefs.supabaseUserName = user.callSign
                    prefs.supabaseUserRole = user.operatorRole
                }
                prefs.isGuestBypass = false

                logActivity(
                    eventType = "AUTH_LOGIN",
                    title = "Operator Authenticated",
                    details = "Call-Sign '${prefs.supabaseUserName}' signed in via Supabase cloud auth."
                )

                Result.success(authRes)
            } else {
                val errorMsg = parseErrorMessage(response.errorBody()?.string())
                Result.failure(Exception(errorMsg))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun signUp(
        email: String,
        pass: String,
        callSign: String,
        role: String
    ): Result<SupabaseAuthResponse> {
        return try {
            val request = SupabaseSignUpRequest(
                email = email.trim(),
                password = pass,
                data = mapOf(
                    "full_name" to callSign.trim(),
                    "call_sign" to callSign.trim(),
                    "role" to role
                )
            )
            val response = SupabaseClient.api.signUp(request)

            if (response.isSuccessful && response.body() != null) {
                val authRes = response.body()!!

                if (!authRes.accessToken.isNullOrBlank()) {
                    prefs.supabaseAccessToken = authRes.accessToken
                    SupabaseClient.setAuthToken(authRes.accessToken)
                    prefs.supabaseRefreshToken = authRes.refreshToken
                    prefs.supabaseUserEmail = authRes.user?.email ?: email
                    prefs.supabaseUserName = callSign.ifBlank { "Operator" }
                    prefs.supabaseUserRole = role
                    prefs.isGuestBypass = false
                } else {
                    // Email verification required
                    prefs.supabaseUserEmail = email
                    prefs.supabaseUserName = callSign.ifBlank { "Operator" }
                    prefs.supabaseUserRole = role
                }

                logActivity(
                    eventType = "AUTH_SIGNUP",
                    title = "New Operator Call-Sign Created",
                    details = "New identity created: $callSign ($role) - $email"
                )

                Result.success(authRes)
            } else {
                val errorMsg = parseErrorMessage(response.errorBody()?.string())
                Result.failure(Exception(errorMsg))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun loginAsGuestBypass() {
        prefs.isGuestBypass = true
        prefs.supabaseUserEmail = "operator.guest@kaevex.defense"
        prefs.supabaseUserName = "Guest SOC Commander"
        prefs.supabaseUserRole = "Lead Incident Responder"

        logActivity(
            eventType = "GUEST_BYPASS",
            title = "Guest SOC Session Initialized",
            details = "Operator bypassed cloud auth to enter offline/demo cyber command center."
        )
    }

    fun signOut() {
        logActivity(
            eventType = "AUTH_LOGOUT",
            title = "Operator Deauthenticated",
            details = "Session closed for ${prefs.supabaseUserName ?: "Operator"}."
        )
        scope.launch {
            try {
                SupabaseClient.api.logout()
            } catch (_: Exception) {}
        }
        prefs.clearSupabaseSession()
        SupabaseClient.setAuthToken(null)
    }

    fun logActivity(eventType: String, title: String, details: String) {
        val email = prefs.supabaseUserEmail
        val devInfo = deviceInfo

        // 1. Immediately record in local SQLite cache
        val localId = localCache.insertMobileLog(
            eventType = eventType,
            title = title,
            details = details,
            deviceInfo = devInfo,
            userEmail = email,
            isSynced = false
        )

        // 2. Asynchronously upload to Supabase
        scope.launch {
            try {
                val logItem = MobileActivityLog(
                    userEmail = email,
                    eventType = eventType,
                    title = title,
                    details = details,
                    deviceInfo = devInfo
                )
                val resp = SupabaseClient.api.insertActivityLog(log = logItem)
                if (resp.isSuccessful) {
                    localCache.markMobileLogSynced(localId)
                }
            } catch (_: Exception) {
                // Ignore network errors; log remains safely persisted in local SQLite cache
            }
        }
    }

    fun getRecentLogs(): List<MobileActivityLog> {
        return localCache.getRecentMobileLogs(50)
    }

    private fun parseErrorMessage(rawJson: String?): String {
        if (rawJson.isNullOrBlank()) return "Authentication request failed. Please check network connection."
        return try {
            val json = JSONObject(rawJson)
            json.optString("msg", "")
                .ifEmpty { json.optString("message", "") }
                .ifEmpty { json.optString("error_description", "") }
                .ifEmpty { "Authentication failed: $rawJson" }
        } catch (_: Exception) {
            rawJson
        }
    }
}
