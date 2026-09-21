package com.kaevex.fireware.domain.network

import android.content.Context
import com.kaevex.fireware.domain.device.DeviceSecurityInspector
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

data class DiscoveredHost(
    val ip: String,
    val port: Int,
    val pingMs: Long,
    val isKaevexService: Boolean
)

class HostDiscoveryScanner(context: Context) {

    private val inspector = DeviceSecurityInspector(context)

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(1200, TimeUnit.MILLISECONDS)
        .readTimeout(1200, TimeUnit.MILLISECONDS)
        .build()

    suspend fun quickPingHost(ip: String, port: Int = 9009): DiscoveredHost? = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        try {
            val socket = Socket()
            socket.connect(InetSocketAddress(ip, port), 1000)
            socket.close()
            val latency = System.currentTimeMillis() - start

            // Verify Kaevex HTTP endpoint
            val isKaevex = try {
                val req = Request.Builder()
                    .url("http://$ip:$port/api/v1/ping")
                    .build()
                val resp = httpClient.newCall(req).execute()
                resp.isSuccessful
            } catch (_: Exception) {
                false
            }

            DiscoveredHost(ip = ip, port = port, pingMs = latency, isKaevexService = isKaevex)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun autoScanSubnet(onFound: (DiscoveredHost) -> Unit) = withContext(Dispatchers.IO) {
        val localIp = inspector.inspectHardware().localIpAddress
        val candidates = mutableListOf<String>()

        // 1. Always prioritize emulator loopback and local gateway
        candidates.add("10.0.2.2")
        candidates.add("127.0.0.1")

        if (localIp.contains(".") && localIp != "127.0.0.1") {
            val prefix = localIp.substringBeforeLast(".")
            candidates.add("$prefix.1")
            candidates.add("$prefix.2")
            candidates.add("$prefix.100")
            candidates.add("$prefix.101")
            candidates.add("$prefix.150")
            candidates.add("$prefix.200")
            // Also check surrounding addresses
            val myLast = localIp.substringAfterLast(".").toIntOrNull() ?: 10
            for (offset in -5..5) {
                val candidate = myLast + offset
                if (candidate in 1..254 && candidate != myLast) {
                    candidates.add("$prefix.$candidate")
                }
            }
        }

        coroutineScope {
            candidates.distinct().map { targetIp ->
                launch {
                    val result = quickPingHost(targetIp, 9009)
                    if (result != null) {
                        withContext(Dispatchers.Main) {
                            onFound(result)
                        }
                    }
                }
            }
        }
    }
}
