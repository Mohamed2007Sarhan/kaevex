package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class AiChatRequest(
    @SerializedName("team") val team: String = "blue", // blue, red, purple, yellow, green
    @SerializedName("prompt") val prompt: String,
    @SerializedName("api_key") val apiKey: String? = null,
    @SerializedName("model") val model: String = "deepseek-ai/DeepSeek-V4-Pro-0813"
)

data class AiChatResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("provider") val provider: String = "Together AI",
    @SerializedName("model") val model: String = "deepseek-ai/DeepSeek-V4-Pro-0813",
    @SerializedName("is_fallback") val isFallback: Boolean = false,
    @SerializedName("fallback_reason") val fallbackReason: String = "",
    @SerializedName("team") val team: String = "blue",
    @SerializedName("prompt") val prompt: String = "",
    @SerializedName("reply") val reply: String = "",
    @SerializedName("recommendations") val recommendations: List<String> = emptyList(),
    @SerializedName("action") val action: AiAction? = null
)

data class AiAction(
    @SerializedName("action_type") val actionType: String, // LOCKDOWN, SCAN, BOOT_AUDIT, BAN_IP, REMEDIATE_CVE
    @SerializedName("label") val label: String,
    @SerializedName("target") val target: String = "",
    @SerializedName("danger_level") val dangerLevel: String = "HIGH" // HIGH, MEDIUM, LOW
)

data class AiConfigResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("provider") val provider: String = "Together AI",
    @SerializedName("model") val model: String = "deepseek-ai/DeepSeek-V4-Pro-0813",
    @SerializedName("host") val host: String = "api.together.xyz",
    @SerializedName("has_key") val hasKey: Boolean = false,
    @SerializedName("key_masked") val keyMasked: String = ""
)

data class AiConfigRequest(
    @SerializedName("api_key") val apiKey: String,
    @SerializedName("model") val model: String = "deepseek-ai/DeepSeek-V4-Pro-0813"
)

data class ChatMessage(
    val id: String = java.util.UUID.randomUUID().toString(),
    val sender: MessageSender,
    val text: String,
    val timestamp: String,
    val team: String = "blue",
    val action: AiAction? = null,
    val isExecuting: Boolean = false,
    val executionResult: String? = null
)

enum class MessageSender {
    USER,
    SOC_AGENT
}
