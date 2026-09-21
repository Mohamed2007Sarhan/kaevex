package com.kaevex.fireware.ui.screens.settings

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.SettingsViewModel

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onSignOut: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val prefs = remember { com.kaevex.fireware.data.local.SecurePreferences(context) }

    var apiKeyInput by remember(state.togetherApiKey) { mutableStateOf(state.togetherApiKey) }
    var aiModelInput by remember(state.aiModel) { mutableStateOf(state.aiModel) }
    var exportSuccessMessage by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(AbyssBlack)
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Official Kaevex Brand Showcase Card
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(16.dp))
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                androidx.compose.foundation.Image(
                    painter = androidx.compose.ui.res.painterResource(id = com.kaevex.fireware.R.drawable.kaevex_logo),
                    contentDescription = "Kaevex Cyber Systems",
                    modifier = Modifier
                        .size(80.dp)
                        .clip(CircleShape)
                        .background(AbyssBlack)
                        .border(1.5.dp, NeonCyan.copy(alpha = 0.6f), CircleShape)
                        .padding(8.dp)
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "KAEVEX CYBER SYSTEMS",
                    color = TextPrimary,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Unified Endpoint Defense & SOC Command Platform",
                    color = NeonCyan,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "Win32 C11 Sub-Millisecond Architecture • Port 9009 REST API",
                    color = TextMuted,
                    fontSize = 10.sp,
                    style = Typography.labelSmall
                )
            }
        }

        // Section: Connected Operator Profile & Supabase Auth
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(CircleShape)
                            .background(NeonCyan.copy(alpha = 0.15f))
                            .border(1.dp, NeonCyan, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Person,
                            contentDescription = null,
                            tint = NeonCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = prefs.supabaseUserName ?: "Active SOC Operator",
                            color = TextPrimary,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = prefs.supabaseUserRole ?: "Cyber Defense Specialist",
                            color = NeonCyan,
                            fontSize = 11.sp
                        )
                        Text(
                            text = prefs.supabaseUserEmail ?: "offline.operator@kaevex.local",
                            color = TextMuted,
                            fontSize = 10.sp
                        )
                    }

                    // Cloud link status pill
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(if (prefs.isGuestBypass) WarningAmber.copy(alpha = 0.2f) else CleanEmerald.copy(alpha = 0.2f))
                            .border(0.5.dp, if (prefs.isGuestBypass) WarningAmber else CleanEmerald, RoundedCornerShape(6.dp))
                            .padding(horizontal = 6.dp, vertical = 3.dp)
                    ) {
                        Text(
                            text = if (prefs.isGuestBypass) "OFFLINE GUEST" else "SUPABASE SYNC",
                            color = if (prefs.isGuestBypass) WarningAmber else CleanEmerald,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                OutlinedButton(
                    onClick = onSignOut,
                    border = androidx.compose.foundation.BorderStroke(1.dp, ThreatCrimson.copy(alpha = 0.7f)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = ThreatCrimson),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        imageVector = Icons.Default.Logout,
                        contentDescription = "Sign Out",
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "DEAUTHENTICATE / SIGN OUT",
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Section: Real Telemetry & Supabase Activity Logs
        item {
            var recentLogs by remember { mutableStateOf(emptyList<com.kaevex.fireware.data.supabase.MobileActivityLog>()) }
            val cache = remember { com.kaevex.fireware.data.local.KaevexLocalCache(context) }

            LaunchedEffect(Unit) {
                recentLogs = cache.getRecentMobileLogs(15)
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Dns, contentDescription = null, tint = CyberPurple)
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text("MOBILE SOC TELEMETRY LOGS", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Text("Synced with Supabase Cloud & Local Vault", color = TextSecondary, fontSize = 10.sp)
                        }
                    }

                    IconButton(onClick = { recentLogs = cache.getRecentMobileLogs(15) }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh Logs", tint = NeonCyan, modifier = Modifier.size(18.dp))
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                if (recentLogs.isEmpty()) {
                    Text("No mobile telemetry logs recorded yet.", color = TextMuted, fontSize = 11.sp)
                } else {
                    recentLogs.take(6).forEach { log ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(SocSurfaceElevated)
                                .padding(horizontal = 8.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(NeonCyan)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(log.title, color = TextPrimary, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                Text(log.details, color = TextMuted, fontSize = 10.sp, maxLines = 1)
                            }
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = log.eventType,
                                color = CyberPurple,
                                fontSize = 9.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        item {
            Text(
                text = "SECURITY & NODE PREFERENCES",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
            Text(
                text = "Kaevex Mobile SOC Configuration Vault",
                color = TextSecondary,
                fontSize = 12.sp
            )
        }

        // Section 1: Biometric Security Settings
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Fingerprint, contentDescription = null, tint = NeonCyan)
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text("Biometric Defense Gate", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text("Require Fingerprint/Face before Lockdown & Scans", color = TextSecondary, fontSize = 10.sp)
                        }
                    }
                    Switch(
                        checked = state.biometricsEnabled,
                        onCheckedChange = { viewModel.setBiometrics(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = AbyssBlack,
                            checkedTrackColor = NeonCyan,
                            uncheckedTrackColor = SocBorder
                        )
                    )
                }
            }
        }

        // Section 2: Connection & Fallback Preferences
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.WifiTethering, contentDescription = null, tint = WarningAmber)
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text("Demo / Offline Fallback Mode", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text("Simulate live Windows host data when offline", color = TextSecondary, fontSize = 10.sp)
                        }
                    }
                    Switch(
                        checked = state.demoModeEnabled,
                        onCheckedChange = { viewModel.setDemoMode(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = AbyssBlack,
                            checkedTrackColor = WarningAmber,
                            uncheckedTrackColor = SocBorder
                        )
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))
                HorizontalDivider(color = SocBorder, thickness = 0.5.dp)
                Spacer(modifier = Modifier.height(14.dp))

                Text("Telemetry Auto-Refresh Interval", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(5, 10, 30).forEach { interval ->
                        val isSelected = state.refreshIntervalSec == interval
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .background(if (isSelected) NeonCyan.copy(alpha = 0.2f) else AbyssBlack)
                                .border(1.dp, if (isSelected) NeonCyan else SocBorder, RoundedCornerShape(8.dp))
                                .clickable { viewModel.setRefreshInterval(interval) }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "${interval}s",
                                color = if (isSelected) NeonCyan else TextSecondary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        // Section 3: AI Configuration (Together AI / DeepSeek)
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Psychology, contentDescription = null, tint = CyberPurple)
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("AI Cloud Engine (Together AI)", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = apiKeyInput,
                    onValueChange = { apiKeyInput = it },
                    label = { Text("Together AI Key (sk-together-...)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberPurple,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    )
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = aiModelInput,
                    onValueChange = { aiModelInput = it },
                    label = { Text("Target Model") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberPurple,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    )
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = { viewModel.saveAiConfig(apiKeyInput, aiModelInput) },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberPurple, contentColor = TextPrimary),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Save AI Configuration", fontWeight = FontWeight.Bold)
                }
            }
        }

        // Section 4: Forensic JSON Log Exporter
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.FileDownload, contentDescription = null, tint = EmeraldSafe)
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("Export Forensic Report", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Generate and share a cryptographic JSON audit artifact of the active Windows system posture, UEFI state, CVE inventory, and alerts history.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = {
                        val reportJson = viewModel.exportForensicReport(context)
                        val sendIntent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, reportJson)
                            putExtra(Intent.EXTRA_TITLE, "Kaevex SOC Forensic Report")
                            type = "application/json"
                        }
                        context.startActivity(Intent.createChooser(sendIntent, "Share SOC Forensic Report"))
                        exportSuccessMessage = "Forensic JSON report compiled successfully."
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldSafe.copy(alpha = 0.2f),
                        contentColor = EmeraldSafe
                    ),
                    border = androidx.compose.foundation.BorderStroke(1.dp, EmeraldSafe),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Share Cryptographic Report", fontWeight = FontWeight.Bold)
                }

                if (exportSuccessMessage != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = exportSuccessMessage!!,
                        color = EmeraldSafe,
                        fontSize = 11.sp,
                        style = Typography.labelSmall
                    )
                }
            }
        }
    }
}
