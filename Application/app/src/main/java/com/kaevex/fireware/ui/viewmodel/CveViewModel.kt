package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.model.CveItem
import com.kaevex.fireware.data.model.CveReportResponse
import com.kaevex.fireware.domain.repository.KaevexRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface CveUiState {
    data object Loading : CveUiState
    data class Success(
        val report: CveReportResponse,
        val selectedTab: Int = 0 // 0 = Patched, 1 = Active Risks
    ) : CveUiState
    data class Error(val message: String) : CveUiState
}

class CveViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = KaevexRepository(application)
    private val supabaseDb = com.kaevex.fireware.domain.repository.SupabaseDbRepository(application)

    private val _uiState = MutableStateFlow<CveUiState>(CveUiState.Loading)
    val uiState: StateFlow<CveUiState> = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    init {
        loadCveData()
    }

    fun loadCveData() {
        viewModelScope.launch {
            _uiState.value = CveUiState.Loading
            val result = repository.getCves()
            result.onSuccess {
                _uiState.value = CveUiState.Success(it)
            }.onFailure {
                _uiState.value = CveUiState.Error(it.localizedMessage ?: "Failed to retrieve CVE database")
            }
        }
    }

    fun selectTab(index: Int) {
        val current = _uiState.value
        if (current is CveUiState.Success) {
            _uiState.value = current.copy(selectedTab = index)
        }
    }

    fun remediateCve(item: CveItem) {
        viewModelScope.launch {
            _userMessage.emit("Dispatching 1-Click Remediation for ${item.softwareName}...")
            val result = repository.remediateCve(item.cveId, item.softwareName)
            result.onSuccess { res ->
                _userMessage.emit(res.message)
                supabaseDb.saveCveRemediation(item.cveId)
                // Move item from active to patched locally in state
                val current = _uiState.value
                if (current is CveUiState.Success) {
                    val updatedActive = current.report.activeRisks.filter { it.cveId != item.cveId }
                    val updatedPatched = current.report.patchedCves.toMutableList().apply {
                        add(0, item.copy(patchStatus = "WINGET_PATCHED", canAutoRemediate = false, mitigationDate = "NOW"))
                    }
                    _uiState.value = current.copy(
                        report = current.report.copy(
                            activeRisks = updatedActive,
                            patchedCves = updatedPatched
                        )
                    )
                }
            }.onFailure {
                _userMessage.emit("Remediation error: ${it.message}")
            }
        }
    }
}
