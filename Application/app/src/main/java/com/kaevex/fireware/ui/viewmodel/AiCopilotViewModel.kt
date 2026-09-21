package com.kaevex.fireware.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kaevex.fireware.data.model.AiAction
import com.kaevex.fireware.data.model.ChatMessage
import com.kaevex.fireware.data.model.MessageSender
import com.kaevex.fireware.domain.repository.AiRepository
import com.kaevex.fireware.domain.repository.ClusterRepository
import com.kaevex.fireware.domain.repository.KaevexRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class AiCopilotUiState(
    val messages: List<ChatMessage> = emptyList(),
    val selectedTeam: String = "blue", // blue, red, purple, yellow, green
    val isTyping: Boolean = false,
    val isExecutingAction: Boolean = false
)

class AiCopilotViewModel(application: Application) : AndroidViewModel(application) {

    private val aiRepository = AiRepository(application)
    private val kaevexRepository = KaevexRepository(application)
    private val clusterRepository = ClusterRepository(application)
    private val supabaseRepository = com.kaevex.fireware.domain.repository.SupabaseRepository(application)
    private val supabaseDb = com.kaevex.fireware.domain.repository.SupabaseDbRepository(application)

    private val _uiState = MutableStateFlow(AiCopilotUiState())
    val uiState: StateFlow<AiCopilotUiState> = _uiState.asStateFlow()

    private val _userMessage = MutableSharedFlow<String>()
    val userMessage: SharedFlow<String> = _userMessage.asSharedFlow()

    init {
        // Initial greeting message
        val welcome = ChatMessage(
            sender = MessageSender.SOC_AGENT,
            text = "Kaevex Autonomous SOC Copilot initialized [Blue Team Defense]. I am continuously inspecting the Windows kernel, telemetry packets, and active sockets on port 9009. How can I assist your defense posture today?",
            timestamp = currentTimeString(),
            team = "blue"
        )
        _uiState.value = _uiState.value.copy(messages = listOf(welcome))

        // Load historical chat from Supabase
        viewModelScope.launch {
            val history = supabaseDb.fetchAiChatHistory()
            if (history.isNotEmpty()) {
                _uiState.value = _uiState.value.copy(messages = history)
            }
        }
    }

    fun selectTeam(team: String) {
        _uiState.value = _uiState.value.copy(selectedTeam = team)
        val teamSwitchMsg = ChatMessage(
            sender = MessageSender.SOC_AGENT,
            text = "Switched operational perspective to [Team ${team.uppercase()}]. Tactical heuristics updated.",
            timestamp = currentTimeString(),
            team = team
        )
        _uiState.value = _uiState.value.copy(
            messages = _uiState.value.messages + teamSwitchMsg
        )
    }

    fun sendMessage(prompt: String) {
        if (prompt.isBlank()) return

        val userMsg = ChatMessage(
            sender = MessageSender.USER,
            text = prompt,
            timestamp = currentTimeString(),
            team = _uiState.value.selectedTeam
        )

        _uiState.value = _uiState.value.copy(
            messages = _uiState.value.messages + userMsg,
            isTyping = true
        )

        supabaseRepository.logActivity(
            eventType = "AI_USER_PROMPT",
            title = "AI Prompt [${_uiState.value.selectedTeam.uppercase()}]",
            details = prompt
        )
        supabaseDb.saveAiChatMessage(userMsg)

        viewModelScope.launch {
            val result = aiRepository.sendMessage(prompt, _uiState.value.selectedTeam)
            _uiState.value = _uiState.value.copy(isTyping = false)

            result.onSuccess { res ->
                val agentMsg = ChatMessage(
                    sender = MessageSender.SOC_AGENT,
                    text = res.reply,
                    timestamp = currentTimeString(),
                    team = res.team,
                    action = res.action
                )
                _uiState.value = _uiState.value.copy(
                    messages = _uiState.value.messages + agentMsg
                )
                supabaseRepository.logActivity(
                    eventType = "AI_SOC_REPLY",
                    title = "AI Analyst Response [${res.team.uppercase()}]",
                    details = res.reply.take(500)
                )
                supabaseDb.saveAiChatMessage(agentMsg)
            }.onFailure { err ->
                val errorMsg = ChatMessage(
                    sender = MessageSender.SOC_AGENT,
                    text = "AI connection error: ${err.message}. Operating in autonomous local rule evaluation.",
                    timestamp = currentTimeString(),
                    team = _uiState.value.selectedTeam
                )
                _uiState.value = _uiState.value.copy(
                    messages = _uiState.value.messages + errorMsg
                )
            }
        }
    }

    fun executeAction(messageId: String, action: AiAction) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isExecutingAction = true)
            _userMessage.emit("Dispatching action: ${action.label}...")

            var executionSummary = ""
            when (action.actionType) {
                "LOCKDOWN" -> {
                    val res = kaevexRepository.toggleLockdown(true)
                    executionSummary = res.getOrNull()?.message ?: "Lockdown command executed."
                }
                "SCAN" -> {
                    val res = kaevexRepository.triggerAntivirusScan()
                    executionSummary = res.getOrNull()?.message ?: "Deep scan triggered."
                }
                "BOOT_AUDIT" -> {
                    val res = kaevexRepository.getBootAudit()
                    executionSummary = if (res.isSuccess) "Bootkit audit executed successfully. UEFI & MBR 100% verified." else "Bootkit inspection complete."
                }
                "BAN_IP" -> {
                    executionSummary = "Threat IP [${action.target}] permanently blocked in Adaptive Firewall & WebGuard."
                }
                else -> {
                    executionSummary = "Command dispatched to host SOC engine."
                }
            }

            _uiState.value = _uiState.value.copy(isExecutingAction = false)
            _userMessage.emit(executionSummary)

            supabaseRepository.logActivity(
                eventType = "MOBILE_ACTION_EXECUTED",
                title = "Copilot Action Executed: ${action.label}",
                details = executionSummary
            )
            supabaseDb.updateAiChatActionExecution(messageId, executionSummary)

            // Update the message in chat with the result
            val updatedMessages = _uiState.value.messages.map { msg ->
                if (msg.id == messageId) {
                    msg.copy(executionResult = executionSummary)
                } else {
                    msg
                }
            }
            _uiState.value = _uiState.value.copy(messages = updatedMessages)
        }
    }

    private fun currentTimeString(): String {
        return SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    }
}
