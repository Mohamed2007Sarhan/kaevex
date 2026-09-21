package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.model.DashboardResponse
import com.kaevex.fireware.domain.repository.KaevexRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

sealed interface DashboardUiState {
    data object Loading : DashboardUiState
    data class Success(val data: DashboardResponse, val isPolling: Boolean = false) : DashboardUiState
    data class Error(val message: String) : DashboardUiState
}

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = KaevexRepository(application)
    private val prefs = SecurePreferences(application)
    private val supabaseRepository = com.kaevex.fireware.domain.repository.SupabaseRepository(application)
    private val supabaseDb = com.kaevex.fireware.domain.repository.SupabaseDbRepository(application)
    private val deviceInspector = com.kaevex.fireware.domain.device.DeviceSecurityInspector(application)

    private val _uiState = MutableStateFlow<DashboardUiState>(DashboardUiState.Loading)
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    private val _devicePosture = MutableStateFlow<com.kaevex.fireware.domain.device.FullDeviceReport?>(null)
    val devicePosture: StateFlow<com.kaevex.fireware.domain.device.FullDeviceReport?> = _devicePosture.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    private var pollingJob: Job? = null

    init {
        refreshDevicePosture()
        startPolling()
    }

    fun refreshDevicePosture() {
        _devicePosture.value = deviceInspector.inspectDevice()
    }

    fun auditAndSyncPhonePosture() {
        val report = deviceInspector.inspectDevice()
        _devicePosture.value = report
        val hw = report.hardware
        val sec = report.security

        supabaseRepository.logActivity(
            eventType = "MOBILE_POSTURE_AUDIT",
            title = "Mobile SOC Endpoint Audited (${sec.securityVerdict})",
            details = "IP: ${hw.localIpAddress} (${hw.connectionType}) | RAM: ${hw.availableRamMb}MB/${hw.totalRamMb}MB | Battery: ${hw.batteryPercent}% | Storage: ${hw.freeStorageGb}GB/${hw.totalStorageGb}GB | Root: ${sec.isRooted} | ADB: ${sec.isAdbEnabled} | DevMode: ${sec.isDevModeEnabled} | Security Score: ${sec.integrityScore}/100"
        )
        supabaseDb.saveDeviceTelemetry(report)

        viewModelScope.launch {
            _userMessage.emit("Mobile security posture analyzed & synced to Supabase (Score: ${sec.integrityScore}/100)")
        }
    }

    fun startPolling() {
        pollingJob?.cancel()
        pollingJob = viewModelScope.launch {
            while (isActive) {
                loadDashboard(isBackground = _uiState.value is DashboardUiState.Success)
                val delaySec = prefs.refreshIntervalSec.coerceIn(2, 60)
                delay(delaySec * 1000L)
            }
        }
    }

    fun refresh() {
        viewModelScope.launch {
            loadDashboard(isBackground = false)
        }
    }

    private suspend fun loadDashboard(isBackground: Boolean) {
        if (!isBackground && _uiState.value !is DashboardUiState.Success) {
            _uiState.value = DashboardUiState.Loading
        }
        val result = repository.getDashboard()
        result.onSuccess { data ->
            _uiState.value = DashboardUiState.Success(data, isPolling = isBackground)
            supabaseDb.saveSecurityAlerts(data.recentAlerts)
        }.onFailure { err ->
            if (_uiState.value !is DashboardUiState.Success) {
                _uiState.value = DashboardUiState.Error(err.localizedMessage ?: "Failed to connect to SOC")
            }
        }
    }

    fun toggleFirewallLockdown() {
        viewModelScope.launch {
            val currentLocked = when (val s = _uiState.value) {
                is DashboardUiState.Success -> s.data.security.firewallLocked
                else -> false
            }
            val target = !currentLocked
            supabaseRepository.logActivity(
                eventType = "MOBILE_LOCKDOWN_COMMAND",
                title = if (target) "Firewall Panic Lockdown Engaged" else "Firewall Lockdown Lifted",
                details = "Triggered from mobile command center for server ${prefs.activeServerIp}:${prefs.activeServerPort}"
            )
            val result = repository.toggleLockdown(target)
            result.onSuccess { res ->
                _userMessage.emit(res.message)
                loadDashboard(isBackground = true)
            }.onFailure {
                _userMessage.emit("Failed to toggle lockdown: ${it.message}")
            }
        }
    }

    fun triggerAntivirusScan() {
        viewModelScope.launch {
            supabaseRepository.logActivity(
                eventType = "MOBILE_ANTIVIRUS_SCAN",
                title = "Endpoint Deep Scan Initiated",
                details = "Manual AV scan dispatched from mobile SOC for ${prefs.activeServerIp}"
            )
            val result = repository.triggerAntivirusScan()
            result.onSuccess {
                _userMessage.emit(it.message)
                loadDashboard(isBackground = true)
            }.onFailure {
                _userMessage.emit("Scan trigger error: ${it.message}")
            }
        }
    }

    fun clearAlerts() {
        viewModelScope.launch {
            supabaseRepository.logActivity(
                eventType = "MOBILE_ALERTS_CLEARED",
                title = "SOC Alerts Cleared",
                details = "Operator cleared active alert log from mobile device"
            )
            supabaseDb.clearSecurityAlerts()
            val result = repository.clearAlerts()
            result.onSuccess {
                _userMessage.emit(it.message)
                loadDashboard(isBackground = true)
            }.onFailure {
                _userMessage.emit("Clear alerts error: ${it.message}")
            }
        }
    }
}
