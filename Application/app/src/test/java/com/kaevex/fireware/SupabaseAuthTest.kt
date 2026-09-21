package com.kaevex.fireware

import com.google.gson.Gson
import com.kaevex.fireware.data.supabase.*
import org.junit.Assert.*
import org.junit.Test

class SupabaseAuthTest {

    private val gson = Gson()

    @Test
    fun testSupabaseSignUpRequestSerialization() {
        val req = SupabaseSignUpRequest(
            email = "commander@kaevex.com",
            password = "SecretPassword123!",
            data = mapOf(
                "call_sign" to "Viper-1",
                "role" to "Lead SOC Analyst"
            )
        )
        val json = gson.toJson(req)
        assertTrue(json.contains("commander@kaevex.com"))
        assertTrue(json.contains("Viper-1"))
        assertTrue(json.contains("Lead SOC Analyst"))
    }

    @Test
    fun testSupabaseSignInRequestSerialization() {
        val req = SupabaseSignInRequest(
            email = "commander@kaevex.com",
            password = "SecretPassword123!"
        )
        val json = gson.toJson(req)
        assertTrue(json.contains("commander@kaevex.com"))
        assertTrue(json.contains("SecretPassword123!"))
    }

    @Test
    fun testSupabaseAuthResponseParsing() {
        val json = """
            {
                "access_token": "mock_jwt_token_header.payload.sig",
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": "mock_refresh_token_value",
                "user": {
                    "id": "uuid-12345-67890",
                    "aud": "authenticated",
                    "role": "authenticated",
                    "email": "commander@kaevex.com",
                    "user_metadata": {
                        "call_sign": "Viper-1",
                        "role": "Incident Responder"
                    }
                }
            }
        """.trimIndent()

        val response = gson.fromJson(json, SupabaseAuthResponse::class.java)
        assertEquals("mock_jwt_token_header.payload.sig", response.accessToken)
        assertEquals("bearer", response.tokenType)
        assertEquals("commander@kaevex.com", response.user?.email)
        assertEquals("Viper-1", response.user?.callSign)
        assertEquals("Incident Responder", response.user?.operatorRole)
    }

    @Test
    fun testMobileActivityLogSerialization() {
        val log = MobileActivityLog(
            userEmail = "operator@kaevex.com",
            eventType = "AI_USER_PROMPT",
            title = "AI Prompt [BLUE]",
            details = "User queried threat telemetry for active socket 9009",
            deviceInfo = "Google Pixel 7 (Android 14, API 34)"
        )
        val json = gson.toJson(log)
        assertTrue(json.contains("AI_USER_PROMPT"))
        assertTrue(json.contains("operator@kaevex.com"))
        assertTrue(json.contains("Google Pixel 7"))
    }

    @Test
    fun testSupabaseConfigIntegrity() {
        assertEquals("https://lqvijkatveozunxzlaid.supabase.co", SupabaseConfig.URL)
        assertEquals("sb_publishable_87D-MbAPOprfjvY8CkLNnQ_KvIOBjhj", SupabaseConfig.ANON_KEY)
    }
}
