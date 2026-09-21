package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.GsonBuilder
import com.kaevex.fireware.data.demo.DemoDataProvider
import com.kaevex.fireware.data.local.KaevexLocalCache
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.domain.repository.AiRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SettingsUiState(
    val biometricsEnabled: Boolean = true,
    val demoModeEnabled: Boolean = true,
    val refreshIntervalSec: Int = 5,
    val requestTimeoutSec: Long = 5,
    val togetherApiKey: String = "",
    val aiModel: String = "deepseek-ai/DeepSeek-V4-Pro-0813",
    val activeIp: String = "10.0.2.2",
    val activePort: Int = 9009
)

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = SecurePreferences(application)
    private val localCache = KaevexLocalCache(application)
    private val aiRepository = AiRepository(application)
    private val supabaseDb = com.kaevex.fireware.domain.repository.SupabaseDbRepository(application)

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    init {
        loadSettings()
    }

    fun loadSettings() {
        _uiState.value = SettingsUiState(
            biometricsEnabled = prefs.biometricsEnabled,
            demoModeEnabled = prefs.demoModeEnabled,
            refreshIntervalSec = prefs.refreshIntervalSec,
            requestTimeoutSec = prefs.requestTimeoutSec,
            togetherApiKey = prefs.togetherApiKey,
            aiModel = prefs.aiModel,
            activeIp = prefs.activeServerIp,
            activePort = prefs.activeServerPort
        )
    }

    fun setBiometrics(enabled: Boolean) {
        prefs.biometricsEnabled = enabled
        _uiState.value = _uiState.value.copy(biometricsEnabled = enabled)
        supabaseDb.saveOperatorSettings()
        viewModelScope.launch {
            _userMessage.emit(if (enabled) "Biometric authentication enforced for critical actions." else "Biometric authentication disabled.")
        }
    }

    fun setDemoMode(enabled: Boolean) {
        prefs.demoModeEnabled = enabled
        _uiState.value = _uiState.value.copy(demoModeEnabled = enabled)
        viewModelScope.launch {
            _userMessage.emit(if (enabled) "Simulated Demo & Fallback Mode ENABLED" else "Live Backend Mode (Connecting to port 9009)")
        }
    }

    fun setRefreshInterval(interval: Int) {
        prefs.refreshIntervalSec = interval
        _uiState.value = _uiState.value.copy(refreshIntervalSec = interval)
        supabaseDb.saveOperatorSettings()
    }

    fun setRequestTimeout(timeout: Long) {
        prefs.requestTimeoutSec = timeout
        _uiState.value = _uiState.value.copy(requestTimeoutSec = timeout)
        supabaseDb.saveOperatorSettings()
    }

    fun saveAiConfig(apiKey: String, model: String) {
        viewModelScope.launch {
            val result = aiRepository.updateAiConfig(apiKey, model)
            result.onSuccess {
                _uiState.value = _uiState.value.copy(togetherApiKey = apiKey, aiModel = model)
                supabaseDb.saveOperatorSettings()
                _userMessage.emit("AI configuration saved successfully & synced with Supabase.")
            }.onFailure {
                _userMessage.emit("Failed to save AI config: ${it.message}")
            }
        }
    }

    fun exportForensicReport(context: Context): String {
        val gson = GsonBuilder().setPrettyPrinting().create()
        val report = mapOf(
            "report_generated_at" to System.currentTimeMillis().toString(),
            "target_server" to "${prefs.activeServerIp}:${prefs.activeServerPort}",
            "dashboard_telemetry" to DemoDataProvider.getDemoDashboard(false),
            "boot_audit_forensics" to DemoDataProvider.getDemoBootAudit(),
            "cve_vulnerability_matrix" to DemoDataProvider.getDemoCveReport(),
            "alerts_history" to localCache.getRecentAlerts(50)
        )
        return gson.toJson(report)
    }
}
