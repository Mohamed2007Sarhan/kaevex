package com.kaevex.fireware.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.kaevex.fireware.data.model.ServerNode

class SecurePreferences(context: Context) {

    private val prefs: SharedPreferences = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            "kaevex_secure_vault",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        // Fallback for emulators without hardware Keystore support
        context.getSharedPreferences("kaevex_soc_prefs", Context.MODE_PRIVATE)
    }

    private val gson = Gson()

    companion object {
        private const val KEY_ACTIVE_IP = "active_server_ip"
        private const val KEY_ACTIVE_PORT = "active_server_port"
        private const val KEY_ACTIVE_NAME = "active_server_name"
        private const val KEY_AUTH_TOKEN = "auth_token"
        private const val KEY_BIOMETRICS_ENABLED = "biometrics_enabled"
        private const val KEY_DEMO_MODE = "demo_mode_fallback"
        private const val KEY_REFRESH_INTERVAL = "refresh_interval_sec"
        private const val KEY_REQUEST_TIMEOUT = "request_timeout_sec"
        private const val KEY_TOGETHER_API_KEY = "together_api_key"
        private const val KEY_AI_MODEL = "ai_model"
        private const val KEY_SAVED_SERVERS = "saved_servers_json"
        private const val KEY_SUPABASE_TOKEN = "supabase_access_token"
        private const val KEY_SUPABASE_REFRESH = "supabase_refresh_token"
        private const val KEY_SUPABASE_EMAIL = "supabase_user_email"
        private const val KEY_SUPABASE_NAME = "supabase_user_name"
        private const val KEY_SUPABASE_ROLE = "supabase_user_role"
        private const val KEY_IS_GUEST_BYPASS = "is_guest_bypass"
    }

    var activeServerIp: String
        get() = prefs.getString(KEY_ACTIVE_IP, "10.0.2.2") ?: "10.0.2.2"
        set(value) = prefs.edit().putString(KEY_ACTIVE_IP, value).apply()

    var activeServerPort: Int
        get() = prefs.getInt(KEY_ACTIVE_PORT, 9009)
        set(value) = prefs.edit().putInt(KEY_ACTIVE_PORT, value).apply()

    var activeServerName: String
        get() = prefs.getString(KEY_ACTIVE_NAME, "Primary SOC Node (Host)") ?: "Primary SOC Node (Host)"
        set(value) = prefs.edit().putString(KEY_ACTIVE_NAME, value).apply()

    var authToken: String?
        get() = prefs.getString(KEY_AUTH_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_AUTH_TOKEN, value).apply()

    var biometricsEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRICS_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_BIOMETRICS_ENABLED, value).apply()

    var demoModeEnabled: Boolean
        get() = prefs.getBoolean(KEY_DEMO_MODE, false)
        set(value) = prefs.edit().putBoolean(KEY_DEMO_MODE, value).apply()

    var refreshIntervalSec: Int
        get() = prefs.getInt(KEY_REFRESH_INTERVAL, 5)
        set(value) = prefs.edit().putInt(KEY_REFRESH_INTERVAL, value).apply()

    var requestTimeoutSec: Long
        get() = prefs.getLong(KEY_REQUEST_TIMEOUT, 5L)
        set(value) = prefs.edit().putLong(KEY_REQUEST_TIMEOUT, value).apply()

    var togetherApiKey: String
        get() = prefs.getString(KEY_TOGETHER_API_KEY, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TOGETHER_API_KEY, value).apply()

    var aiModel: String
        get() = prefs.getString(KEY_AI_MODEL, "deepseek-ai/DeepSeek-V4-Pro-0813") ?: "deepseek-ai/DeepSeek-V4-Pro-0813"
        set(value) = prefs.edit().putString(KEY_AI_MODEL, value).apply()

    var supabaseAccessToken: String?
        get() = prefs.getString(KEY_SUPABASE_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_SUPABASE_TOKEN, value).apply()

    var supabaseRefreshToken: String?
        get() = prefs.getString(KEY_SUPABASE_REFRESH, null)
        set(value) = prefs.edit().putString(KEY_SUPABASE_REFRESH, value).apply()

    var supabaseUserEmail: String?
        get() = prefs.getString(KEY_SUPABASE_EMAIL, null)
        set(value) = prefs.edit().putString(KEY_SUPABASE_EMAIL, value).apply()

    var supabaseUserName: String?
        get() = prefs.getString(KEY_SUPABASE_NAME, null)
        set(value) = prefs.edit().putString(KEY_SUPABASE_NAME, value).apply()

    var supabaseUserRole: String?
        get() = prefs.getString(KEY_SUPABASE_ROLE, null)
        set(value) = prefs.edit().putString(KEY_SUPABASE_ROLE, value).apply()

    var isGuestBypass: Boolean
        get() = prefs.getBoolean(KEY_IS_GUEST_BYPASS, false)
        set(value) = prefs.edit().putBoolean(KEY_IS_GUEST_BYPASS, value).apply()

    val isAuthenticated: Boolean
        get() = !supabaseAccessToken.isNullOrBlank() || isGuestBypass

    fun clearSupabaseSession() {
        prefs.edit()
            .remove(KEY_SUPABASE_TOKEN)
            .remove(KEY_SUPABASE_REFRESH)
            .remove(KEY_SUPABASE_EMAIL)
            .remove(KEY_SUPABASE_NAME)
            .remove(KEY_SUPABASE_ROLE)
            .putBoolean(KEY_IS_GUEST_BYPASS, false)
            .apply()
    }

    fun getSavedServers(): List<ServerNode> {
        val json = prefs.getString(KEY_SAVED_SERVERS, null) ?: return defaultServers()
        return try {
            val type = object : TypeToken<List<ServerNode>>() {}.type
            gson.fromJson(json, type) ?: defaultServers()
        } catch (e: Exception) {
            defaultServers()
        }
    }

    fun saveServers(servers: List<ServerNode>) {
        val json = gson.toJson(servers)
        prefs.edit().putString(KEY_SAVED_SERVERS, json).apply()
    }

    private fun defaultServers(): List<ServerNode> {
        return listOf(
            ServerNode(
                id = 1,
                name = "Primary SOC Node (Host)",
                ip = activeServerIp,
                port = activeServerPort,
                role = "Master",
                status = "ONLINE",
                pingMs = 4,
                threats = 0,
                isLocked = false,
                isActive = true
            ),
            ServerNode(
                id = 2,
                name = "Office Master Cluster",
                ip = "192.168.1.150",
                port = 9009,
                role = "Master",
                status = "ONLINE",
                pingMs = 12,
                threats = 0,
                isLocked = false,
                isActive = false
            ),
            ServerNode(
                id = 3,
                name = "AWS Web Security Gateway",
                ip = "34.218.90.11",
                port = 9009,
                role = "Web-Server",
                status = "ONLINE",
                pingMs = 42,
                threats = 1,
                isLocked = false,
                isActive = false
            ),
            ServerNode(
                id = 4,
                name = "PostgreSQL DB Vault Node",
                ip = "192.168.1.180",
                port = 9009,
                role = "DB-Server",
                status = "ONLINE",
                pingMs = 8,
                threats = 0,
                isLocked = false,
                isActive = false
            )
        )
    }
}
