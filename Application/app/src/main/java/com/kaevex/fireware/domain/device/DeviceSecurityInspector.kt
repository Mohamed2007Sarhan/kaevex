package com.kaevex.fireware.domain.device

import android.app.ActivityManager
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface

data class DeviceHardwarePosture(
    val batteryPercent: Int,
    val isCharging: Boolean,
    val availableRamMb: Long,
    val totalRamMb: Long,
    val freeStorageGb: Double,
    val totalStorageGb: Double,
    val localIpAddress: String,
    val connectionType: String,
    val isVpnActive: Boolean,
    val manufacturer: String,
    val model: String,
    val osVersion: String,
    val apiLevel: Int,
    val securityPatch: String
)

data class DeviceSecurityPosture(
    val isRooted: Boolean,
    val rootIndicators: List<String>,
    val isAdbEnabled: Boolean,
    val isDevModeEnabled: Boolean,
    val isKeyguardSecure: Boolean,
    val integrityScore: Int,
    val securityVerdict: String
)

data class FullDeviceReport(
    val hardware: DeviceHardwarePosture,
    val security: DeviceSecurityPosture
)

class DeviceSecurityInspector(private val context: Context) {

    fun inspectDevice(): FullDeviceReport {
        val hardware = inspectHardware()
        val security = inspectSecurity()
        return FullDeviceReport(hardware, security)
    }

    fun inspectHardware(): DeviceHardwarePosture {
        // Battery
        val batteryFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryStatus: Intent? = context.registerReceiver(null, batteryFilter)
        val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val batteryPct = if (level >= 0 && scale > 0) ((level / scale.toFloat()) * 100).toInt() else 100
        val status = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL

        // RAM
        val actManager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        actManager?.getMemoryInfo(memInfo)
        val availRamMb = memInfo.availMem / (1024 * 1024)
        val totalRamMb = memInfo.totalMem / (1024 * 1024)

        // Storage
        val stat = StatFs(Environment.getDataDirectory().path)
        val blockSize = stat.blockSizeLong
        val totalBlocks = stat.blockCountLong
        val availBlocks = stat.availableBlocksLong
        val totalStorageGb = String.format(java.util.Locale.US, "%.1f", (totalBlocks * blockSize).toDouble() / (1024 * 1024 * 1024)).toDoubleOrNull() ?: 0.0
        val freeStorageGb = String.format(java.util.Locale.US, "%.1f", (availBlocks * blockSize).toDouble() / (1024 * 1024 * 1024)).toDoubleOrNull() ?: 0.0

        // Network & IP
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNet = connectivity?.activeNetwork
        val caps = connectivity?.getNetworkCapabilities(activeNet)

        val connType = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi LAN"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular 5G/LTE"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            else -> "Offline / Local Only"
        }
        val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

        val localIp = getLocalIpAddress()

        return DeviceHardwarePosture(
            batteryPercent = batteryPct,
            isCharging = isCharging,
            availableRamMb = availRamMb,
            totalRamMb = totalRamMb,
            freeStorageGb = freeStorageGb,
            totalStorageGb = totalStorageGb,
            localIpAddress = localIp,
            connectionType = connType,
            isVpnActive = isVpn,
            manufacturer = Build.MANUFACTURER.replaceFirstChar { it.uppercase() },
            model = Build.MODEL,
            osVersion = Build.VERSION.RELEASE,
            apiLevel = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "2026-03-01"
        )
    }

    fun inspectSecurity(): DeviceSecurityPosture {
        val rootIndicators = mutableListOf<String>()

        // 1. Check su binary paths
        val suPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        for (path in suPaths) {
            if (File(path).exists()) {
                rootIndicators.add("SU binary found: $path")
            }
        }

        // 2. Build tags test-keys
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) {
            rootIndicators.add("Build tagged with 'test-keys' (Custom ROM)")
        }

        val isRooted = rootIndicators.isNotEmpty()

        // 3. ADB / USB Debugging
        val isAdb = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }

        // 4. Developer Settings
        val isDevMode = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }

        // 5. Keyguard Secure
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val isKeyguardSecure = keyguard?.isDeviceSecure ?: false

        // Compute Mobile Integrity Score (0 - 100)
        var score = 100
        if (isRooted) score -= 40
        if (isAdb) score -= 15
        if (isDevMode) score -= 10
        if (!isKeyguardSecure) score -= 20
        score = score.coerceIn(0, 100)

        val verdict = when {
            score >= 90 -> "HIGH INTEGRITY (SECURE ENDPOINT)"
            score >= 70 -> "MODERATE RISK (DEV FLAGS ACTIVE)"
            else -> "HIGH RISK COMPROMISED (ROOT / UNSECURED)"
        }

        return DeviceSecurityPosture(
            isRooted = isRooted,
            rootIndicators = rootIndicators,
            isAdbEnabled = isAdb,
            isDevModeEnabled = isDevMode,
            isKeyguardSecure = isKeyguardSecure,
            integrityScore = score,
            securityVerdict = verdict
        )
    }

    private fun getLocalIpAddress(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isLoopback || !iface.isUp) continue
                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        return addr.hostAddress ?: "127.0.0.1"
                    }
                }
            }
        } catch (_: Exception) {}
        return "127.0.0.1"
    }
}
