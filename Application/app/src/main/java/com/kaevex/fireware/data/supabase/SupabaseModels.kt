package com.kaevex.fireware.data.supabase

import com.google.gson.annotations.SerializedName

data class SupabaseSignUpRequest(
    @SerializedName("email") val email: String,
    @SerializedName("password") val password: String,
    @SerializedName("data") val data: Map<String, String> = emptyMap()
)

data class SupabaseSignInRequest(
    @SerializedName("email") val email: String,
    @SerializedName("password") val password: String
)

data class SupabaseAuthResponse(
    @SerializedName("access_token") val accessToken: String? = null,
    @SerializedName("token_type") val tokenType: String? = null,
    @SerializedName("expires_in") val expiresIn: Long? = null,
    @SerializedName("refresh_token") val refreshToken: String? = null,
    @SerializedName("user") val user: SupabaseUser? = null,
    @SerializedName("error") val error: String? = null,
    @SerializedName("error_description") val errorDescription: String? = null,
    @SerializedName("msg") val msg: String? = null,
    @SerializedName("message") val message: String? = null
)

data class SupabaseUser(
    @SerializedName("id") val id: String? = null,
    @SerializedName("aud") val aud: String? = null,
    @SerializedName("role") val role: String? = null,
    @SerializedName("email") val email: String? = null,
    @SerializedName("phone") val phone: String? = null,
    @SerializedName("user_metadata") val userMetadata: Map<String, Any>? = null,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("last_sign_in_at") val lastSignInAt: String? = null
) {
    val callSign: String
        get() = (userMetadata?.get("call_sign") as? String)
            ?: (userMetadata?.get("full_name") as? String)
            ?: email?.substringBefore("@")
            ?: "Operator"

    val operatorRole: String
        get() = (userMetadata?.get("role") as? String)
            ?: "SOC Operator"
}

data class MobileActivityLog(
    @SerializedName("id") val id: Long? = null,
    @SerializedName("user_id") val userId: String? = null,
    @SerializedName("user_email") val userEmail: String? = null,
    @SerializedName("event_type") val eventType: String,
    @SerializedName("title") val title: String,
    @SerializedName("details") val details: String,
    @SerializedName("device_info") val deviceInfo: String,
    @SerializedName("created_at") val createdAt: String? = null
)
