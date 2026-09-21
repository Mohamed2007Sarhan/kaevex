package com.kaevex.fireware.domain.repository

import android.content.Context
import com.google.gson.Gson
import com.kaevex.fireware.data.api.ApiClient
import com.kaevex.fireware.data.demo.DemoDataProvider
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.data.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class AiRepository(private val context: Context) {

    private val prefs = SecurePreferences(context)
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    suspend fun sendMessage(prompt: String, team: String): Result<AiChatResponse> = withContext(Dispatchers.IO) {
        val apiKey = prefs.togetherApiKey.ifBlank { null }
        val model = prefs.aiModel

        // 1. Try Windows C11 Security Backend on Port 9009
        try {
            val response = ApiClient.getService().sendAiChat(
                AiChatRequest(
                    team = team,
                    prompt = prompt,
                    apiKey = apiKey,
                    model = model
                )
            )
            if (response.isSuccessful && response.body() != null) {
                return@withContext Result.success(response.body()!!)
            }
        } catch (_: Exception) {
            // Backend unreachable, attempt direct cloud LLM if key exists
        }

        // 2. Direct Cloud LLM Call if API Key is configured in Settings
        if (!apiKey.isNullOrBlank()) {
            val cloudResult = callCloudLlm(apiKey, model, prompt, team)
            if (cloudResult.isSuccess) {
                return@withContext cloudResult
            }
        }

        // 3. Fallback to Autonomous Rule-Based Response with NLP Intent Parsing
        Result.success(DemoDataProvider.parseAiChatResponse(prompt, team))
    }

    private fun callCloudLlm(apiKey: String, model: String, prompt: String, team: String): Result<AiChatResponse> {
        return try {
            val endpoint = if (model.contains("deepseek", ignoreCase = true) && !apiKey.startsWith("tog_")) {
                "https://api.deepseek.com/v1/chat/completions"
            } else {
                "https://api.together.xyz/v1/chat/completions"
            }

            val systemRolePrompt = when (team.lowercase()) {
                "red" -> "You are Kaevex Red Team Offensive Copilot. Analyze vulnerabilities, adversarial CVE exploitation vectors, and penetration strategies concisely for a mobile SOC commander."
                "purple" -> "You are Kaevex Purple Team Adversary Emulation Copilot. Correlate offensive techniques with defensive mitigations concisely."
                "yellow" -> "You are Kaevex Yellow Team Architecture Copilot. Recommend infrastructure and code hardening measures."
                "green" -> "You are Kaevex Green Team Automation Copilot. Assist with automated scripting and remediation pipelines."
                else -> "You are Kaevex Blue Team Cyber Defense Copilot. Provide rapid host security analysis, incident response, and proactive lockdown guidance concisely."
            }

            val jsonBody = JSONObject().apply {
                put("model", model)
                val messagesArray = JSONArray().apply {
                    put(JSONObject().apply {
                        put("role", "system")
                        put("content", systemRolePrompt)
                    })
                    put(JSONObject().apply {
                        put("role", "user")
                        put("content", prompt)
                    })
                }
                put("messages", messagesArray)
                put("temperature", 0.3)
                put("max_tokens", 800)
            }

            val request = Request.Builder()
                .url(endpoint)
                .addHeader("Authorization", "Bearer $apiKey")
                .addHeader("Content-Type", "application/json")
                .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
                .build()

            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful && response.body != null) {
                val respString = response.body!!.string()
                val parsedJson = JSONObject(respString)
                val replyContent = parsedJson.getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content")

                // Extract potential interactive action chips from response
                val simulated = DemoDataProvider.parseAiChatResponse(prompt, team)
                Result.success(
                    AiChatResponse(
                        team = team,
                        reply = replyContent,
                        model = model,
                        action = simulated.action
                    )
                )
            } else {
                Result.failure(Exception("Cloud LLM returned HTTP ${response.code}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun updateAiConfig(apiKey: String, model: String): Result<ActionResponse> = withContext(Dispatchers.IO) {
        prefs.togetherApiKey = apiKey
        prefs.aiModel = model

        try {
            val response = ApiClient.getService().updateAiConfig(AiConfigRequest(apiKey, model))
            if (response.isSuccessful && response.body() != null) {
                return@withContext Result.success(response.body()!!)
            }
        } catch (_: Exception) {}

        Result.success(ActionResponse("success", "ai_config", "AI configuration saved in secure vault."))
    }
}
