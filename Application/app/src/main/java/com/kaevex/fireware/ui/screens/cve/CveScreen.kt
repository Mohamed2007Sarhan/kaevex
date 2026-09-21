package com.kaevex.fireware.ui.screens.cve

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.data.model.CveItem
import com.kaevex.fireware.data.model.CveReportResponse
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.CveUiState
import com.kaevex.fireware.ui.viewmodel.CveViewModel

@Composable
fun CveScreen(
    viewModel: CveViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    when (val s = state) {
        is CveUiState.Loading -> {
            Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = NeonCyan)
            }
        }
        is CveUiState.Error -> {
            Box(modifier = modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = ThreatCrimson)
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(s.message, color = TextPrimary)
                    Button(onClick = { viewModel.loadCveData() }) { Text("Retry") }
                }
            }
        }
        is CveUiState.Success -> {
            CveContent(
                report = s.report,
                selectedTab = s.selectedTab,
                onTabSelect = { viewModel.selectTab(it) },
                onRemediate = { viewModel.remediateCve(it) },
                modifier = modifier
            )
        }
    }
}

@Composable
fun CveContent(
    report: CveReportResponse,
    selectedTab: Int,
    onTabSelect: (Int) -> Unit,
    onRemediate: (CveItem) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(AbyssBlack)
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Section 1: CIS Benchmark Compliance Banner
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
                            imageVector = Icons.Default.FactCheck,
                            contentDescription = "Compliance",
                            tint = NeonCyan,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = report.compliance.statusLabel,
                            color = TextPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(EmeraldSafe.copy(alpha = 0.2f))
                            .border(1.dp, EmeraldSafe, RoundedCornerShape(6.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "${report.compliance.cisBenchmarkScore}% SCORE",
                            color = EmeraldSafe,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            style = Typography.labelSmall
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Passed: ${report.compliance.passedRules} rules",
                        color = EmeraldSafe,
                        fontSize = 11.sp,
                        style = Typography.labelSmall
                    )
                    Text(
                        text = "Pending Fixes: ${report.compliance.failedRules} rules",
                        color = WarningAmber,
                        fontSize = 11.sp,
                        style = Typography.labelSmall
                    )
                    Text(
                        text = "NIST CSF: ${report.compliance.nistScore}%",
                        color = NeonCyan,
                        fontSize = 11.sp,
                        style = Typography.labelSmall
                    )
                }
            }
        }

        // Section 2: Tab Bar (Patched CVEs vs Active Risks)
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(SocSurface)
                    .padding(4.dp)
            ) {
                TabButton(
                    title = "Patched CVEs (${report.patchedCves.size})",
                    isSelected = selectedTab == 0,
                    onClick = { onTabSelect(0) },
                    modifier = Modifier.weight(1f)
                )
                TabButton(
                    title = "Active Risks (${report.activeRisks.size})",
                    isSelected = selectedTab == 1,
                    onClick = { onTabSelect(1) },
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Section 3: List Items
        val itemsToShow = if (selectedTab == 0) report.patchedCves else report.activeRisks

        if (itemsToShow.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (selectedTab == 0) "No patched CVE records." else "Zero active vulnerabilities detected! Host is 100% up-to-date.",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        } else {
            items(itemsToShow) { item ->
                CveItemCard(
                    cve = item,
                    onRemediate = { onRemediate(item) }
                )
            }
        }
    }
}

@Composable
fun TabButton(
    title: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (isSelected) SocSurfaceElevated else Color.Transparent)
            .clickable { onClick() }
            .padding(vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = title,
            color = if (isSelected) NeonCyan else TextSecondary,
            fontSize = 12.sp,
            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
        )
    }
}

@Composable
fun CveItemCard(
    cve: CveItem,
    onRemediate: () -> Unit
) {
    val sevColor = when (cve.severity.uppercase()) {
        "CRITICAL" -> ThreatCrimson
        "HIGH" -> WarningAmber
        "MEDIUM" -> CyberPurple
        else -> NeonCyan
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
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(sevColor.copy(alpha = 0.2f))
                        .border(1.dp, sevColor, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "${cve.severity} ${cve.cvssScore}",
                        color = sevColor,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        style = Typography.labelSmall
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                Text(
                    text = cve.cveId,
                    color = TextPrimary,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    style = Typography.labelLarge
                )
            }

            Text(
                text = if (cve.mitigationDate.isNotBlank()) cve.mitigationDate else cve.patchStatus,
                color = TextSecondary,
                fontSize = 10.sp,
                style = Typography.labelSmall
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = cve.softwareName,
            color = NeonCyan,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold
        )

        if (cve.title.isNotBlank()) {
            Text(
                text = cve.title,
                color = TextSecondary,
                fontSize = 11.sp,
                lineHeight = 15.sp
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Version: ${cve.installedVersion} ${if (cve.patchedVersion.isNotBlank()) "➔ ${cve.patchedVersion}" else ""}",
                color = TextMuted,
                fontSize = 10.sp,
                style = Typography.labelSmall
            )

            if (cve.canAutoRemediate) {
                Button(
                    onClick = onRemediate,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonCyan,
                        contentColor = AbyssBlack
                    ),
                    shape = RoundedCornerShape(6.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.height(30.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.AutoFixHigh,
                        contentDescription = "Remediate",
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("1-Click Remediate", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = "Patched",
                        tint = EmeraldSafe,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "MITIGATED",
                        color = EmeraldSafe,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        style = Typography.labelSmall
                    )
                }
            }
        }
    }
}
