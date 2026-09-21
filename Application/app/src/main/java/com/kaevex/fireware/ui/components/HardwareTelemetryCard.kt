package com.kaevex.fireware.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.ui.theme.*

@Composable
fun HardwareTelemetryRow(
    cpuPercent: Int,
    ramPercent: Int,
    activeSockets: Int,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        TelemetryCard(
            title = "CPU LOAD",
            value = "$cpuPercent%",
            progress = cpuPercent / 100f,
            icon = Icons.Default.DeveloperBoard,
            accentColor = if (cpuPercent > 80) ThreatCrimson else NeonCyan,
            modifier = Modifier.weight(1f)
        )
        TelemetryCard(
            title = "RAM USAGE",
            value = "$ramPercent%",
            progress = ramPercent / 100f,
            icon = Icons.Default.Memory,
            accentColor = if (ramPercent > 85) WarningAmber else CyberPurple,
            modifier = Modifier.weight(1f)
        )
        TelemetryCard(
            title = "TCP SOCKETS",
            value = "$activeSockets",
            progress = (activeSockets / 200f).coerceIn(0.1f, 1f),
            icon = Icons.Default.Sensors,
            accentColor = EmeraldSafe,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
fun TelemetryCard(
    title: String,
    value: String,
    progress: Float,
    icon: ImageVector,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    val animatedProgress by animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        label = "progress_$title"
    )

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(SocSurface)
            .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
            .padding(10.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = title,
                color = TextSecondary,
                fontSize = 9.sp,
                fontWeight = FontWeight.Medium,
                style = Typography.labelSmall
            )
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = accentColor,
                modifier = Modifier.size(14.dp)
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = value,
            color = TextPrimary,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            style = Typography.titleLarge
        )

        Spacer(modifier = Modifier.height(8.dp))

        LinearProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier
                .fillMaxWidth()
                .height(4.dp)
                .clip(RoundedCornerShape(2.dp)),
            color = accentColor,
            trackColor = SocBorder
        )
    }
}
