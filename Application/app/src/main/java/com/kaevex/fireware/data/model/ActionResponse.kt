package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class ActionResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("action") val action: String = "",
    @SerializedName("message") val message: String = "",
    @SerializedName("locked") val locked: Boolean? = null
)

data class LockdownRequest(
    @SerializedName("enable") val enable: Int // 1 = lock, 0 = unlock
)

data class FilePathRequest(
    @SerializedName("file_path") val filePath: String
)

data class ThreatItem(
    @SerializedName("id") val id: Int = 0,
    @SerializedName("file_path") val filePath: String,
    @SerializedName("threat_type") val threatType: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("entropy") val entropy: Double = 0.0,
    @SerializedName("sha256") val sha256: String = "",
    @SerializedName("status") val status: String = "ACTIVE"
)

data class ConnectionItem(
    @SerializedName("pid") val pid: Int,
    @SerializedName("process") val process: String,
    @SerializedName("local") val local: String,
    @SerializedName("remote") val remote: String,
    @SerializedName("state") val state: Int
)

data class ConnectionsResponse(
    @SerializedName("connections") val connections: List<ConnectionItem> = emptyList(),
    @SerializedName("total") val total: Int = 0
)

data class PingResponse(
    @SerializedName("status") val status: String = "online",
    @SerializedName("platform") val platform: String = "Kaevex SOC Engine",
    @SerializedName("version") val version: String = "1.0.0-PROD"
)
