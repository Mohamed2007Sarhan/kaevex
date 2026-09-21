package com.kaevex.fireware.ui.screens.dashboard

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.data.model.AlertItem
import com.kaevex.fireware.data.model.DashboardResponse
import com.kaevex.fireware.data.model.EngineInfo
import com.kaevex.fireware.ui.components.HardwareTelemetryRow
import com.kaevex.fireware.ui.components.HostIntegrityGauge
import com.kaevex.fireware.ui.components.SparklineChart
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.DashboardUiState
import com.kaevex.fireware.ui.viewmodel.DashboardViewModel

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onNavigateToBootAudit: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    when (val s = state) {
        is DashboardUiState.Loading -> {
            Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = NeonCyan)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Connecting to Kaevex SOC Engine...", color = TextSecondary, fontSize = 12.sp)
                }
            }
        }
        is DashboardUiState.Error -> {
            Box(modifier = modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.Warning, contentDescription = "Error", tint = ThreatCrimson, modifier = Modifier.size(48.dp))
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(s.message, color = TextPrimary, fontWeight = FontWeight.SemiBold)
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { viewModel.refresh() }, colors = ButtonDefaults.buttonColors(containerColor = SocSurfaceElevated)) {
                        Text("Retry Connection", color = NeonCyan)
                    }
                }
            }
        }
        is DashboardUiState.Success -> {
            val devicePosture by viewModel.devicePosture.collectAsState()
            DashboardContent(
                data = s.data,
                devicePosture = devicePosture,
                onScanClick = { viewModel.triggerAntivirusScan() },
                onLockdownClick = { viewModel.toggleFirewallLockdown() },
                onBootAuditClick = onNavigateToBootAudit,
                onClearAlertsClick = { viewModel.clearAlerts() },
                onAuditPhoneClick = { viewModel.auditAndSyncPhonePosture() },
                modifier = modifier
            )
        }
    }
}

@Composable
fun DashboardContent(
    data: DashboardResponse,
    devicePosture: com.kaevex.fireware.domain.device.FullDeviceReport?,
    onScanClick: () -> Unit,
    onLockdownClick: () -> Unit,
    onBootAuditClick: () -> Unit,
    onClearAlertsClick: () -> Unit,
    onAuditPhoneClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(AbyssBlack)
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Hero Brand Header
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(14.dp))
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                androidx.compose.foundation.Image(
                    painter = androidx.compose.ui.res.painterResource(id = com.kaevex.fireware.R.drawable.kaevex_icon_small),
                    contentDescription = "Kaevex Shield",
                    modifier = Modifier
                        .size(46.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(SocSurfaceElevated)
                        .border(1.dp, NeonCyan.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                        .padding(5.dp)
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "KAEVEX MOBILE SOC",
                        color = TextPrimary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.5.sp
                    )
                    Text(
                        text = "Autonomous Win32 Endpoint Commander",
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(EmeraldSafe.copy(alpha = 0.15f))
                        .border(1.dp, EmeraldSafe.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "PROD v1.0",
                        color = EmeraldSafe,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        style = Typography.labelSmall
                    )
                }
            }
        }

        // Section 1: Host Integrity Radial Meter
        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(16.dp))
                    .padding(vertical = 16.dp, horizontal = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    HostIntegrityGauge(score = data.integrityScore)

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "HOST: ${data.server.hostname}",
                            color = TextPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            style = Typography.labelMedium
                        )
                        Text(
                            text = "•",
                            color = TextMuted
                        )
                        Text(
                            text = "UPTIME: ${data.server.uptimeFormatted}",
                            color = NeonCyan,
                            fontSize = 11.sp,
                            style = Typography.labelMedium
                        )
                    }
                }
            }
        }

        // Section 2: Hardware Telemetry Cards (CPU, RAM, TCP Sockets)
        item {
            HardwareTelemetryRow(
                cpuPercent = data.resources.cpuPercent,
                ramPercent = data.resources.ramPercent,
                activeSockets = data.security.activeConnections
            )
        }

        // Section 3: Proactive Inline WAF Counter & Traffic Wave
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(14.dp))
                    .padding(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.ShieldMoon,
                            contentDescription = "WAF",
                            tint = WarningAmber,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "PROACTIVE INLINE WAF SHIELD",
                            color = TextPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.5.sp
                        )
                    }
                    Text(
                        text = "${data.security.wafBlocked} BLOCKED",
                        color = WarningAmber,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        style = Typography.labelSmall
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "${data.security.wafInspected} HTTP/TCP payloads inspected before reaching host kernel. Intercepted SQLi, XSS, RCE, LFI vectors.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Sparkline traffic wave
                SparklineChart(points = data.traffic.sparkline)
            }
        }

        // Section 3.5: Real Mobile Phone Command Posture (This Device)
        if (devicePosture != null) {
            item {
                val hw = devicePosture.hardware
                val sec = devicePosture.security
                val verdictColor = if (sec.integrityScore >= 90) EmeraldSafe else if (sec.integrityScore >= 70) WarningAmber else ThreatCrimson

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(SocSurface)
                        .border(1.dp, SocBorder, RoundedCornerShape(14.dp))
                        .padding(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Smartphone,
                                contentDescription = "Device",
                                tint = NeonCyan,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "MOBILE CONTROLLER ENDPOINT",
                                color = TextPrimary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp
                            )
                        }

                        // Score Pill
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(verdictColor.copy(alpha = 0.15f))
                                .border(1.dp, verdictColor.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Text(
                                text = "${sec.integrityScore}% INTEGRITY",
                                color = verdictColor,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                style = Typography.labelSmall
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = "${hw.manufacturer} ${hw.model} • Android ${hw.osVersion} (API ${hw.apiLevel})",
                        color = TextPrimary,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    // Telemetry row: IP & Network, Battery, Free RAM
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // IP Badge
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(6.dp))
                                .background(SocSurfaceElevated)
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Column {
                                Text("LOCAL IP", color = TextMuted, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                Text(hw.localIpAddress, color = NeonCyan, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }

                        // Battery Badge
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(6.dp))
                                .background(SocSurfaceElevated)
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Column {
                                Text("BATTERY", color = TextMuted, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                Text("${hw.batteryPercent}% ${if (hw.isCharging) "(⚡)" else ""}", color = EmeraldSafe, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }

                        // RAM Badge
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(6.dp))
                                .background(SocSurfaceElevated)
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Column {
                                Text("AVAIL RAM", color = TextMuted, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                Text("${hw.availableRamMb} MB", color = TextPrimary, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Security check chips
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        // Root chip
                        val rootColor = if (sec.isRooted) ThreatCrimson else EmeraldSafe
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(rootColor.copy(alpha = 0.15f))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(if (sec.isRooted) "ROOT: DETECTED" else "ROOT: CLEAN", color = rootColor, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        }

                        // ADB chip
                        val adbColor = if (sec.isAdbEnabled) WarningAmber else EmeraldSafe
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(adbColor.copy(alpha = 0.15f))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(if (sec.isAdbEnabled) "ADB: ACTIVE" else "ADB: SECURE", color = adbColor, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        }

                        // Keyguard chip
                        val keyColor = if (sec.isKeyguardSecure) EmeraldSafe else WarningAmber
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(keyColor.copy(alpha = 0.15f))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(if (sec.isKeyguardSecure) "SCREEN LOCK: ON" else "NO LOCK", color = keyColor, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedButton(
                        onClick = onAuditPhoneClick,
                        border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(36.dp)
                    ) {
                        Icon(Icons.Default.CloudSync, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("ANALYZE & SYNC PHONE TELEMETRY TO SUPABASE", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Section 4: Quick Action Grid (2x2)
        item {
            Text(
                text = "EXECUTIVE DEFENSE ACTIONS",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
            Spacer(modifier = Modifier.height(8.dp))

            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ActionCard(
                        title = "Deep Antivirus Scan",
                        subtitle = "CryptoAPI & PE inspection",
                        icon = Icons.Default.Search,
                        accentColor = NeonCyan,
                        onClick = onScanClick,
                        modifier = Modifier.weight(1f)
                    )
                    ActionCard(
                        title = if (data.security.firewallLocked) "Unlock Firewall" else "Firewall Lockdown",
                        subtitle = if (data.security.firewallLocked) "Network isolated" else "Isolate host network",
                        icon = if (data.security.firewallLocked) Icons.Default.LockOpen else Icons.Default.Lock,
                        accentColor = if (data.security.firewallLocked) EmeraldSafe else ThreatCrimson,
                        onClick = onLockdownClick,
                        modifier = Modifier.weight(1f)
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ActionCard(
                        title = "Bootkit Audit",
                        subtitle = "UEFI & MBR verification",
                        icon = Icons.Default.Fingerprint,
                        accentColor = CyberPurple,
                        onClick = onBootAuditClick,
                        modifier = Modifier.weight(1f)
                    )
                    ActionCard(
                        title = "Clear Resolved",
                        subtitle = "Wipe resolved alerts",
                        icon = Icons.Default.DoneAll,
                        accentColor = TextSecondary,
                        onClick = onClearAlertsClick,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        // Section 5: Core Defense Engines Status (Horizontal scroll)
        item {
            Text(
                text = "8 CORE DEFENSE ENGINES",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
            Spacer(modifier = Modifier.height(8.dp))

            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                items(data.engines) { engine ->
                    EngineChip(engine = engine)
                }
            }
        }

        // Section 6: Live Alerts Stream
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "REAL-TIME FORENSIC ALERTS",
                    color = NeonCyan,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    style = Typography.labelSmall
                )
                Text(
                    text = "${data.recentAlerts.size} EVENTS",
                    color = TextSecondary,
                    fontSize = 10.sp,
                    style = Typography.labelSmall
                )
            }
        }

        items(data.recentAlerts) { alert ->
            AlertCard(alert = alert)
        }
    }
}

@Composable
fun ActionCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    accentColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
            .clickable { onClick() }
            .padding(12.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = accentColor,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = title,
            color = TextPrimary,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = subtitle,
            color = TextSecondary,
            fontSize = 10.sp,
            maxLines = 1,
            style = Typography.labelSmall
        )
    }
}

@Composable
fun EngineChip(engine: EngineInfo) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(CircleShape)
                .background(if (engine.status == "RUNNING") EmeraldSafe else ThreatCrimson)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Column {
            Text(
                text = engine.name,
                color = TextPrimary,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "v${engine.version} • ${engine.status} • ${engine.load}% load",
                color = TextSecondary,
                fontSize = 9.sp,
                style = Typography.labelSmall
            )
        }
    }
}

@Composable
fun AlertCard(alert: AlertItem) {
    val sevColor = when (alert.severity.uppercase()) {
        "CRITICAL" -> ThreatCrimson
        "HIGH" -> ThreatCrimson
        "WARN", "MEDIUM" -> WarningAmber
        "LOW" -> CyberPurple
        else -> NeonCyan
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(10.dp))
            .padding(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(sevColor.copy(alpha = 0.2f))
                .border(1.dp, sevColor.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                .padding(horizontal = 6.dp, vertical = 3.dp)
        ) {
            Text(
                text = alert.severity,
                color = sevColor,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                style = Typography.labelSmall
            )
        }

        Spacer(modifier = Modifier.width(10.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = alert.source,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = alert.time,
                    color = TextMuted,
                    fontSize = 10.sp,
                    style = Typography.labelSmall
                )
            }
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text = alert.message,
                color = TextSecondary,
                fontSize = 11.sp,
                lineHeight = 15.sp
            )
        }
    }
}
