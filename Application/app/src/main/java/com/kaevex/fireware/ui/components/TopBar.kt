package com.kaevex.fireware.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.data.model.ServerNode
import com.kaevex.fireware.ui.theme.*

@Composable
fun SocTopBar(
    activeServer: ServerNode?,
    onServerBadgeClick: () -> Unit,
    onPanicLockdownClick: () -> Unit,
    onSettingsClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    // Pulsing animation for ping dot
    val infiniteTransition = rememberInfiniteTransition(label = "pulse_transition")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(800, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Surface(
        color = AbyssBlack,
        modifier = modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .border(width = 0.5.dp, color = SocBorder, shape = RoundedCornerShape(0.dp))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            // Official Kaevex Brand Emblem
            androidx.compose.foundation.Image(
                painter = androidx.compose.ui.res.painterResource(id = com.kaevex.fireware.R.drawable.kaevex_icon_small),
                contentDescription = "Kaevex Emblem",
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(SocSurface)
                    .border(1.dp, NeonCyan.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                    .padding(4.dp)
            )

            Spacer(modifier = Modifier.width(8.dp))

            // Active Server Badge (Clickable)
            Row(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(8.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(8.dp))
                    .clickable { onServerBadgeClick() }
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Dns,
                    contentDescription = "Active Node",
                    tint = NeonCyan,
                    modifier = Modifier.size(16.dp)
                )

                Spacer(modifier = Modifier.width(8.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = activeServer?.name ?: "Primary SOC Node",
                        color = TextPrimary,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        // Pulsing Green Dot
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(EmeraldSafe.copy(alpha = pulseAlpha))
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "${activeServer?.ip ?: "10.0.2.2"}:${activeServer?.port ?: 9009} • ${activeServer?.pingMs ?: 8}ms",
                            color = TextSecondary,
                            fontSize = 9.sp,
                            style = Typography.labelSmall
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.width(10.dp))

            // Quick Panic Button (Emergency Cluster Lockdown)
            Button(
                onClick = onPanicLockdownClick,
                colors = ButtonDefaults.buttonColors(
                    containerColor = ThreatCrimson,
                    contentColor = TextPrimary
                ),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                modifier = Modifier
                    .height(38.dp)
                    .border(1.dp, ThreatCrimson.copy(alpha = 0.8f), RoundedCornerShape(8.dp))
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = "Emergency Lockdown",
                    tint = Color.White,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "PANIC",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
            }

            Spacer(modifier = Modifier.width(6.dp))

            // Settings Icon Button
            IconButton(
                onClick = onSettingsClick,
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(8.dp))
            ) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings",
                    tint = TextSecondary,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}
