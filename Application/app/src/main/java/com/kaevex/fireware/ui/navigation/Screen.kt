package com.kaevex.fireware.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.ui.graphics.vector.ImageVector

sealed class Screen(
    val route: String,
    val title: String,
    val icon: ImageVector
) {
    data object Dashboard : Screen("dashboard", "SOC Overview", Icons.Default.Shield)
    data object BootAudit : Screen("boot_audit", "Bootkit Vault", Icons.Default.Fingerprint)
    data object CveHub : Screen("cve_hub", "CVE Hub", Icons.Default.BugReport)
    data object Cluster : Screen("cluster", "Cluster Mesh", Icons.Default.Dns)
    data object AiCopilot : Screen("ai_copilot", "AI Copilot", Icons.Default.Psychology)
    data object Settings : Screen("settings", "Settings", Icons.Default.Settings)

    companion object {
        val bottomNavItems = listOf(
            Dashboard,
            BootAudit,
            CveHub,
            Cluster,
            AiCopilot
        )
    }
}
