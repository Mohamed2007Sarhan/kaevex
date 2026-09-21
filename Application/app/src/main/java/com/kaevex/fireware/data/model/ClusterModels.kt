package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class ClusterResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("cluster_count") val clusterCount: Int = 0,
    @SerializedName("servers") val servers: List<ServerNode> = emptyList()
)

data class ServerNode(
    @SerializedName("id") val id: Int = 0,
    @SerializedName("name") val name: String,
    @SerializedName("ip") val ip: String,
    @SerializedName("port") val port: Int = 9009,
    @SerializedName("role") val role: String = "Master", // Master, Web-Server, DB-Server, Worker
    @SerializedName("status") val status: String = "ONLINE", // ONLINE, OFFLINE, ALERT, ISOLATED
    @SerializedName("ping_ms") val pingMs: Int = 12,
    @SerializedName("threats") val threats: Int = 0,
    @SerializedName("is_locked") val isLocked: Boolean = false,
    @SerializedName("token") val token: String = "",
    val isActive: Boolean = false
) {
    val baseUrl: String
        get() = "http://$ip:$port/api/v1/"
}

data class PairRequest(
    @SerializedName("pin") val pin: String,
    @SerializedName("device_id") val deviceId: String,
    @SerializedName("device_name") val deviceName: String
)

data class PairResponse(
    @SerializedName("status") val status: String,
    @SerializedName("message") val message: String = "",
    @SerializedName("token") val token: String = "",
    @SerializedName("expires_in") val expiresIn: Long = 2592000L,
    @SerializedName("server") val server: ServerMeta = ServerMeta()
)

data class ServerMeta(
    @SerializedName("name") val name: String = "Kaevex Host Engine",
    @SerializedName("version") val version: String = "1.0.0-PROD",
    @SerializedName("port") val port: Int = 9009
)

data class AddServerRequest(
    @SerializedName("name") val name: String,
    @SerializedName("ip") val ip: String,
    @SerializedName("port") val port: Int = 9009,
    @SerializedName("role") val role: String = "Master",
    @SerializedName("token") val token: String = ""
)

data class BroadcastRequest(
    @SerializedName("action") val action: String // "lockdown-all" or "scan-all"
)

data class BroadcastResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("action") val action: String = "",
    @SerializedName("affected_servers") val affectedServers: Int = 0,
    @SerializedName("message") val message: String = ""
)
