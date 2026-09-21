package com.kaevex.fireware.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val SocDarkColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = AbyssBlack,
    primaryContainer = SocSurfaceElevated,
    onPrimaryContainer = NeonCyan,
    secondary = CyberPurple,
    onSecondary = AbyssBlack,
    secondaryContainer = SocSurfaceElevated,
    onSecondaryContainer = CyberPurple,
    tertiary = WarningAmber,
    onTertiary = AbyssBlack,
    error = ThreatCrimson,
    onError = TextPrimary,
    background = AbyssBlack,
    onBackground = TextPrimary,
    surface = SocSurface,
    onSurface = TextPrimary,
    surfaceVariant = SocSurfaceElevated,
    onSurfaceVariant = TextSecondary,
    outline = SocBorder,
    outlineVariant = SocBorderGlowing
)

@Composable
fun KaevexTheme(
    content: @Composable () -> Unit
) {
    // Cyber SOC always enforces dark OLED mode
    MaterialTheme(
        colorScheme = SocDarkColorScheme,
        typography = Typography,
        content = content
    )
}