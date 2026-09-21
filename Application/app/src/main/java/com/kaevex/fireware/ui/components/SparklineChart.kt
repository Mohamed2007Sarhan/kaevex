package com.kaevex.fireware.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.kaevex.fireware.ui.theme.NeonCyan
import com.kaevex.fireware.ui.theme.NeonCyanMuted

@Composable
fun SparklineChart(
    points: List<Int>,
    modifier: Modifier = Modifier,
    lineColor: Color = NeonCyan,
    fillColor: Color = NeonCyanMuted
) {
    if (points.isEmpty()) return

    Canvas(modifier = modifier.fillMaxWidth().height(48.dp)) {
        val width = size.width
        val height = size.height
        val maxPoint = (points.maxOrNull() ?: 100).coerceAtLeast(10).toFloat()
        val minPoint = (points.minOrNull() ?: 0).coerceAtLeast(0).toFloat()
        val range = (maxPoint - minPoint).coerceAtLeast(1f)

        val stepX = width / (points.size - 1).coerceAtLeast(1)

        val path = Path()
        val fillPath = Path()

        points.forEachIndexed { index, value ->
            val x = index * stepX
            val normalizedY = 1f - ((value - minPoint) / range)
            val y = normalizedY * (height - 8.dp.toPx()) + 4.dp.toPx()

            if (index == 0) {
                path.moveTo(x, y)
                fillPath.moveTo(x, height)
                fillPath.lineTo(x, y)
            } else {
                path.lineTo(x, y)
                fillPath.lineTo(x, y)
            }

            if (index == points.size - 1) {
                fillPath.lineTo(x, height)
                fillPath.close()
            }
        }

        // Draw filled gradient area underneath
        drawPath(
            path = fillPath,
            brush = Brush.verticalGradient(
                colors = listOf(fillColor, Color.Transparent)
            )
        )

        // Draw glowing line
        drawPath(
            path = path,
            color = lineColor,
            style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
        )

        // Draw node points
        points.forEachIndexed { index, value ->
            val x = index * stepX
            val normalizedY = 1f - ((value - minPoint) / range)
            val y = normalizedY * (height - 8.dp.toPx()) + 4.dp.toPx()
            drawCircle(
                color = lineColor,
                radius = 2.dp.toPx(),
                center = androidx.compose.ui.geometry.Offset(x, y)
            )
        }
    }
}
