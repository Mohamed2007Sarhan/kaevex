package com.kaevex.fireware.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.ui.theme.*

@Composable
fun HostIntegrityGauge(
    score: Int,
    modifier: Modifier = Modifier,
    size: Dp = 190.dp
) {
    val animatedProgress by animateFloatAsState(
        targetValue = score / 100f,
        animationSpec = tween(durationMillis = 1200),
        label = "gauge_progress"
    )

    val gaugeColor = when {
        score >= 85 -> NeonCyan
        score >= 65 -> WarningAmber
        else -> ThreatCrimson
    }

    val gradientBrush = Brush.sweepGradient(
        colors = listOf(
            CyberPurple,
            NeonCyan,
            gaugeColor,
            CyberPurple
        )
    )

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        // Subtle pulsing circular backdrop
        Box(
            modifier = Modifier
                .size(size * 0.76f)
                .background(SocSurfaceElevated, shape = CircleShape)
        )

        Canvas(modifier = Modifier.fillMaxSize().padding(12.dp)) {
            val strokeWidth = 14.dp.toPx()

            // Background Track
            drawArc(
                color = SocBorder,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
            )

            // Active Animated Arc
            drawArc(
                brush = gradientBrush,
                startAngle = 135f,
                sweepAngle = 270f * animatedProgress,
                useCenter = false,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "$score%",
                color = TextPrimary,
                fontSize = 38.sp,
                fontWeight = FontWeight.Bold,
                style = Typography.headlineLarge
            )
            Text(
                text = "HOST INTEGRITY",
                color = gaugeColor,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 1.5.sp,
                style = Typography.labelSmall
            )
            Text(
                text = when {
                    score >= 85 -> "UEFI & KERNEL SECURE"
                    score >= 65 -> "ELEVATED ALERT"
                    else -> "ISOLATION RECOMMENDED"
                },
                color = TextSecondary,
                fontSize = 9.sp,
                style = Typography.labelSmall
            )
        }
    }
}
