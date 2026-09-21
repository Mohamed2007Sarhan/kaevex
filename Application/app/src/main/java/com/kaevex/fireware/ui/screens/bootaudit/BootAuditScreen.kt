package com.kaevex.fireware.ui.screens.bootaudit

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import com.kaevex.fireware.data.model.BootAuditResponse
import com.kaevex.fireware.data.model.CoreBinaryInfo
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.BootAuditUiState
import com.kaevex.fireware.ui.viewmodel.BootAuditViewModel

@Composable
fun BootAuditScreen(
    viewModel: BootAuditViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    when (val s = state) {
        is BootAuditUiState.Loading -> {
            Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = CyberPurple)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Querying UEFI NVRAM & CatRoot2 Catalog...", color = TextSecondary, fontSize = 12.sp)
                }
            }
        }
        is BootAuditUiState.Error -> {
            Box(modifier = modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.ErrorOutline, contentDescription = "Error", tint = ThreatCrimson, modifier = Modifier.size(48.dp))
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(s.message, color = TextPrimary)
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { viewModel.loadBootAudit() }, colors = ButtonDefaults.buttonColors(containerColor = SocSurfaceElevated)) {
                        Text("Retry Forensic Audit", color = NeonCyan)
                    }
                }
            }
        }
        is BootAuditUiState.Success -> {
            BootAuditContent(
                data = s.data,
                onReauditClick = { viewModel.triggerInstantAudit() },
                modifier = modifier
            )
        }
    }
}

@Composable
fun BootAuditContent(
    data: BootAuditResponse,
    onReauditClick: () -> Unit,
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
        // Top Banner: Overall Integrity Badge & Re-audit Button
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "BOOTKIT & UEFI INTEGRITY VAULT",
                        color = NeonCyan,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        style = Typography.labelSmall
                    )
                    Text(
                        text = "Ring-0 Kernel & Boot Sector Forensics",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }

                Button(
                    onClick = onReauditClick,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyberPurple.copy(alpha = 0.2f),
                        contentColor = CyberPurple
                    ),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CyberPurple),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = "Re-Audit", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Re-Audit", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        // Section 1: UEFI Secure Boot Card
        item {
            SecurityInspectionCard(
                title = "UEFI SECURE BOOT (NVRAM)",
                statusText = if (data.uefi.secureBootEnabled) "ACTIVE & ENFORCED" else "DISABLED WARNING",
                isPassed = data.uefi.secureBootEnabled,
                icon = Icons.Default.Shield,
                details = listOf(
                    "NVRAM State" to data.uefi.nvramState,
                    "Firmware Vendor" to data.uefi.vendor,
                    "Setup Mode" to if (data.uefi.setupMode) "VULNERABLE (Unlocked)" else "LOCKED (Hardware Root-of-Trust)"
                ),
                footerNote = data.uefi.details
            )
        }

        // Section 2: BCD Code Integrity Card
        item {
            SecurityInspectionCard(
                title = "BCD CODE INTEGRITY & DRIVER SIGNING",
                statusText = if (data.bcd.testSigningDisabled) "TESTSIGNING DISABLED (STRICT)" else "ALERT: UNSIGNED DRIVERS ALLOWED",
                isPassed = data.bcd.testSigningDisabled,
                icon = Icons.Default.VerifiedUser,
                details = listOf(
                    "Kernel Integrity" to if (data.bcd.driverSigningEnforced) "Enforced (Catalog Signed)" else "Bypassed",
                    "Hypervisor Launch" to data.bcd.hypervisorLaunchType,
                    "NoIntegrityChecks" to if (data.bcd.noIntegrityChecks) "ALERT (Checks Disabled)" else "FALSE (Active Guard)"
                ),
                footerNote = data.bcd.statusText
            )
        }

        // Section 3: ESP & MBR Boot Sector Card
        item {
            SecurityInspectionCard(
                title = "ESP & MBR BOOT SECTOR (SECTOR 0)",
                statusText = if (data.bootSector.mbrSignatureValid) "AUTHENTICODE VALID (0x55AA)" else "SIGNATURE MISMATCH",
                isPassed = data.bootSector.mbrSignatureValid,
                icon = Icons.Default.Storage,
                details = listOf(
                    "MBR Sector 0 Magic" to data.bootSector.mbrMagic,
                    "bootmgfw.efi" to if (data.bootSector.bootmgfwValid) "Valid Authenticode" else "Compromised",
                    "Certificate PCA" to data.bootSector.certSubject,
                    "SHA-256 Hash" to data.bootSector.hashSha256
                ),
                footerNote = data.bootSector.details
            )
        }

        // Section 4: SCM Rogue Services & RAM Drivers Counters
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                StatCounterCard(
                    title = "AUDITED SERVICES",
                    count = "${data.scm.totalServicesAudited}",
                    subtext = "0 Rogue Masqueraders",
                    isGood = data.scm.rogueMasqueraders == 0,
                    modifier = Modifier.weight(1f)
                )
                StatCounterCard(
                    title = "KERNEL DRIVERS IN RAM",
                    count = "${data.scm.kernelDriversInRam}",
                    subtext = "0 Unsigned Drivers",
                    isGood = data.scm.unsignedDriversInRam == 0,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Section 5: Core System Files Verification Table (8 binaries)
        item {
            Text(
                text = "8 CORE WINDOWS SYSTEM BINARIES (CATROOT2)",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
        }

        items(data.coreBinaries) { binary ->
            BinaryVerificationRow(binary = binary)
        }
    }
}

@Composable
fun SecurityInspectionCard(
    title: String,
    statusText: String,
    isPassed: Boolean,
    icon: ImageVector,
    details: List<Pair<String, String>>,
    footerNote: String
) {
    val statusColor = if (isPassed) EmeraldSafe else ThreatCrimson

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
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = statusColor,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = title,
                    color = TextPrimary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(statusColor.copy(alpha = 0.15f))
                    .border(1.dp, statusColor.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = statusText,
                    color = statusColor,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    style = Typography.labelSmall
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        details.forEach { (label, value) ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(text = label, color = TextSecondary, fontSize = 11.sp)
                Text(text = value, color = TextPrimary, fontSize = 11.sp, fontWeight = FontWeight.Medium, style = Typography.labelSmall)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
        HorizontalDivider(color = SocBorder, thickness = 0.5.dp)
        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = "• $footerNote",
            color = TextMuted,
            fontSize = 10.sp,
            lineHeight = 14.sp
        )
    }
}

@Composable
fun StatCounterCard(
    title: String,
    count: String,
    subtext: String,
    isGood: Boolean,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Text(text = title, color = TextSecondary, fontSize = 9.sp, style = Typography.labelSmall)
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = count, color = TextPrimary, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = subtext,
            color = if (isGood) EmeraldSafe else ThreatCrimson,
            fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun BinaryVerificationRow(binary: CoreBinaryInfo) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.CheckCircle,
                contentDescription = "Verified",
                tint = EmeraldSafe,
                modifier = Modifier.size(16.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Column {
                Text(
                    text = binary.binaryName,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = binary.path,
                    color = TextMuted,
                    fontSize = 9.sp,
                    style = Typography.labelSmall
                )
            }
        }

        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(EmeraldSafe.copy(alpha = 0.15f))
                .border(1.dp, EmeraldSafe.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                .padding(horizontal = 6.dp, vertical = 2.dp)
        ) {
            Text(
                text = binary.catRootStatus,
                color = EmeraldSafe,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                style = Typography.labelSmall
            )
        }
    }
}
