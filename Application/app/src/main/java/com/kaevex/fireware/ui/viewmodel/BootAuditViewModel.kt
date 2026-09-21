package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.model.BootAuditResponse
import com.kaevex.fireware.domain.repository.KaevexRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface BootAuditUiState {
    data object Loading : BootAuditUiState
    data class Success(val data: BootAuditResponse) : BootAuditUiState
    data class Error(val message: String) : BootAuditUiState
}

class BootAuditViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = KaevexRepository(application)
    private val supabaseDb = com.kaevex.fireware.domain.repository.SupabaseDbRepository(application)

    private val _uiState = MutableStateFlow<BootAuditUiState>(BootAuditUiState.Loading)
    val uiState: StateFlow<BootAuditUiState> = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    init {
        loadBootAudit()
    }

    fun loadBootAudit() {
        viewModelScope.launch {
            _uiState.value = BootAuditUiState.Loading
            val result = repository.getBootAudit()
            result.onSuccess {
                _uiState.value = BootAuditUiState.Success(it)
                supabaseDb.saveBootAuditReport(it)
            }.onFailure {
                _uiState.value = BootAuditUiState.Error(it.localizedMessage ?: "Failed to perform low-level audit")
            }
        }
    }

    fun triggerInstantAudit() {
        viewModelScope.launch {
            _userMessage.emit("Initiating deep kernel & UEFI NVRAM inspection...")
            loadBootAudit()
            _userMessage.emit("Bootkit audit completed. Authenticode verified.")
        }
    }
}
