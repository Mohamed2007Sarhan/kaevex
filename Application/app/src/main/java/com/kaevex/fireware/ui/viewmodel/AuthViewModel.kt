package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.supabase.MobileActivityLog
import com.kaevex.fireware.domain.repository.SupabaseRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class AuthUiState(
    val isAuthenticated: Boolean = false,
    val isLoading: Boolean = false,
    val isSignUpMode: Boolean = false,
    val email: String = "",
    val password: String = "",
    val callSign: String = "",
    val selectedRole: String = "Lead SOC Analyst",
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val operatorEmail: String? = null,
    val operatorName: String? = null,
    val operatorRole: String? = null,
    val recentActivityLogs: List<MobileActivityLog> = emptyList()
)

class AuthViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SupabaseRepository(application)
    private val prefs = SecurePreferences(application)

    private val _uiState = MutableStateFlow(
        AuthUiState(
            isAuthenticated = prefs.isAuthenticated,
            operatorEmail = prefs.supabaseUserEmail,
            operatorName = prefs.supabaseUserName,
            operatorRole = prefs.supabaseUserRole
        )
    )
    val uiState = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage = _userMessage.asSharedFlow()

    val availableRoles = listOf(
        "Lead SOC Analyst",
        "Incident Responder",
        "Threat Hunter",
        "Cyber Defense Engineer",
        "Red Team Operator"
    )

    init {
        refreshLogs()
    }

    fun toggleAuthMode() {
        _uiState.update {
            it.copy(
                isSignUpMode = !it.isSignUpMode,
                errorMessage = null,
                successMessage = null
            )
        }
    }

    fun onEmailChange(newEmail: String) {
        _uiState.update { it.copy(email = newEmail, errorMessage = null) }
    }

    fun onPasswordChange(newPass: String) {
        _uiState.update { it.copy(password = newPass, errorMessage = null) }
    }

    fun onCallSignChange(newSign: String) {
        _uiState.update { it.copy(callSign = newSign, errorMessage = null) }
    }

    fun onRoleSelected(role: String) {
        _uiState.update { it.copy(selectedRole = role) }
    }

    fun authenticate() {
        val state = _uiState.value
        if (state.email.isBlank() || !state.email.contains("@")) {
            _uiState.update { it.copy(errorMessage = "Please enter a valid operator email address.") }
            return
        }
        if (state.password.length < 6) {
            _uiState.update { it.copy(errorMessage = "Password must be at least 6 characters.") }
            return
        }

        _uiState.update { it.copy(isLoading = true, errorMessage = null, successMessage = null) }

        viewModelScope.launch {
            if (state.isSignUpMode) {
                val callSign = state.callSign.ifBlank { state.email.substringBefore("@") }
                val result = repository.signUp(
                    email = state.email,
                    pass = state.password,
                    callSign = callSign,
                    role = state.selectedRole
                )
                result.onSuccess { authRes ->
                    if (!authRes.accessToken.isNullOrBlank()) {
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                isAuthenticated = true,
                                operatorEmail = prefs.supabaseUserEmail,
                                operatorName = prefs.supabaseUserName,
                                operatorRole = prefs.supabaseUserRole,
                                successMessage = "Operator account activated. Connected to Kaevex SOC Mesh."
                            )
                        }
                    } else {
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                successMessage = "Verification link dispatched to ${state.email}. You can verify or click 'Bypass to SOC' to continue."
                            )
                        }
                    }
                    refreshLogs()
                }.onFailure { err ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            errorMessage = err.message ?: "Failed to initialize operator account."
                        )
                    }
                }
            } else {
                val result = repository.signIn(
                    email = state.email,
                    pass = state.password
                )
                result.onSuccess {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            isAuthenticated = true,
                            operatorEmail = prefs.supabaseUserEmail,
                            operatorName = prefs.supabaseUserName,
                            operatorRole = prefs.supabaseUserRole,
                            successMessage = "Authentication confirmed. Welcome, ${prefs.supabaseUserName}."
                        )
                    }
                    refreshLogs()
                }.onFailure { err ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            errorMessage = err.message ?: "Authentication failed. Verify credentials or use Guest Bypass."
                        )
                    }
                }
            }
        }
    }

    fun bypassToDemo() {
        repository.loginAsGuestBypass()
        _uiState.update {
            it.copy(
                isAuthenticated = true,
                operatorEmail = prefs.supabaseUserEmail,
                operatorName = prefs.supabaseUserName,
                operatorRole = prefs.supabaseUserRole,
                errorMessage = null,
                successMessage = "Guest SOC mode engaged. Offline defenses active."
            )
        }
        refreshLogs()
    }

    fun signOut() {
        repository.signOut()
        _uiState.update {
            it.copy(
                isAuthenticated = false,
                operatorEmail = null,
                operatorName = null,
                operatorRole = null,
                password = "",
                successMessage = "Operator logged out."
            )
        }
        refreshLogs()
    }

    fun refreshLogs() {
        val logs = repository.getRecentLogs()
        _uiState.update { it.copy(recentActivityLogs = logs) }
    }

    fun clearMessages() {
        _uiState.update { it.copy(errorMessage = null, successMessage = null) }
    }
}
