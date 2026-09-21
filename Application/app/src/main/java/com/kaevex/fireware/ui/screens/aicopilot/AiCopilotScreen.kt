package com.kaevex.fireware.ui.screens.aicopilot

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.data.model.AiAction
import com.kaevex.fireware.data.model.ChatMessage
import com.kaevex.fireware.data.model.MessageSender
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.AiCopilotViewModel
import kotlinx.coroutines.launch

@Composable
fun AiCopilotScreen(
    viewModel: AiCopilotViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    val teams = listOf("blue", "red", "purple", "yellow", "green")

    val suggestionChips = listOf(
        "Analyze Latest Alert",
        "Check MBR Integrity",
        "Recommend Hardening Steps",
        "افحص البوت كيت والجهاز",
        "Isolate current server now"
    )

    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) {
            listState.animateScrollToItem(state.messages.size - 1)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AbyssBlack)
    ) {
        // Team Selector Row
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(SocSurface)
                .border(0.5.dp, SocBorder, RoundedCornerShape(0.dp))
                .padding(vertical = 8.dp, horizontal = 12.dp)
        ) {
            Text(
                text = "OPERATIONAL PERSPECTIVE TASKFORCE",
                color = TextSecondary,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
            Spacer(modifier = Modifier.height(6.dp))
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(teams) { team ->
                    val isSelected = state.selectedTeam == team
                    val teamColor = when (team) {
                        "blue" -> NeonCyan
                        "red" -> ThreatCrimson
                        "purple" -> CyberPurple
                        "yellow" -> WarningAmber
                        else -> EmeraldSafe
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (isSelected) teamColor.copy(alpha = 0.2f) else AbyssBlack)
                            .border(
                                width = if (isSelected) 1.5.dp else 1.dp,
                                color = if (isSelected) teamColor else SocBorder,
                                shape = RoundedCornerShape(8.dp)
                            )
                            .clickable { viewModel.selectTeam(team) }
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(teamColor)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "${team.uppercase()} TEAM",
                                color = if (isSelected) TextPrimary else TextSecondary,
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                style = Typography.labelSmall
                            )
                        }
                    }
                }
            }
        }

        // Messages List
        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 14.dp),
            contentPadding = PaddingValues(top = 10.dp, bottom = 10.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(state.messages) { message ->
                ChatBubble(
                    message = message,
                    onExecuteAction = { action ->
                        viewModel.executeAction(message.id, action)
                    }
                )
            }

            if (state.isTyping) {
                item {
                    Row(
                        modifier = Modifier
                            .clip(RoundedCornerShape(10.dp))
                            .background(SocSurface)
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(
                            color = NeonCyan,
                            modifier = Modifier.size(14.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "DeepSeek-V4 SOC Analyst analyzing telemetry...",
                            color = TextSecondary,
                            fontSize = 11.sp,
                            style = Typography.labelSmall
                        )
                    }
                }
            }
        }

        // Quick Suggestion Chips
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(suggestionChips) { chip ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(14.dp))
                        .background(SocSurface)
                        .border(1.dp, SocBorder, RoundedCornerShape(14.dp))
                        .clickable {
                            viewModel.sendMessage(chip)
                        }
                        .padding(horizontal = 10.dp, vertical = 5.dp)
                ) {
                    Text(
                        text = chip,
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Input Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(SocSurface)
                .border(0.5.dp, SocBorder, RoundedCornerShape(0.dp))
                .padding(horizontal = 10.dp, vertical = 8.dp)
                .navigationBarsPadding(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                placeholder = {
                    Text(
                        "Command SOC in English or Arabic (e.g. Isolate, افحص)...",
                        fontSize = 11.sp,
                        color = TextMuted
                    )
                },
                modifier = Modifier.weight(1f),
                singleLine = true,
                shape = RoundedCornerShape(20.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonCyan,
                    unfocusedBorderColor = SocBorder,
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedContainerColor = AbyssBlack,
                    unfocusedContainerColor = AbyssBlack
                )
            )

            Spacer(modifier = Modifier.width(8.dp))

            IconButton(
                onClick = {
                    if (inputText.isNotBlank()) {
                        val text = inputText
                        inputText = ""
                        viewModel.sendMessage(text)
                    }
                },
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
                    .background(NeonCyan)
            ) {
                Icon(
                    imageVector = Icons.Default.Send,
                    contentDescription = "Send",
                    tint = AbyssBlack,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@Composable
fun ChatBubble(
    message: ChatMessage,
    onExecuteAction: (AiAction) -> Unit
) {
    val isUser = message.sender == MessageSender.USER
    val teamColor = when (message.team) {
        "blue" -> NeonCyan
        "red" -> ThreatCrimson
        "purple" -> CyberPurple
        "yellow" -> WarningAmber
        else -> EmeraldSafe
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isUser) Alignment.End else Alignment.Start
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (!isUser) {
                androidx.compose.foundation.Image(
                    painter = androidx.compose.ui.res.painterResource(id = com.kaevex.fireware.R.drawable.kaevex_icon_small),
                    contentDescription = "SOC Avatar",
                    modifier = Modifier
                        .size(16.dp)
                        .clip(CircleShape)
                )
                Spacer(modifier = Modifier.width(5.dp))
            }
            Text(
                text = if (isUser) "DEFENSE OPERATOR" else "KAEVEX SOC [${message.team.uppercase()}]",
                color = if (isUser) TextSecondary else teamColor,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                style = Typography.labelSmall
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = message.timestamp,
                color = TextMuted,
                fontSize = 9.sp,
                style = Typography.labelSmall
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        Box(
            modifier = Modifier
                .widthIn(max = 320.dp)
                .clip(
                    RoundedCornerShape(
                        topStart = 12.dp,
                        topEnd = 12.dp,
                        bottomStart = if (isUser) 12.dp else 2.dp,
                        bottomEnd = if (isUser) 2.dp else 12.dp
                    )
                )
                .background(if (isUser) SocSurfaceElevated else SocSurface)
                .border(
                    width = 1.dp,
                    color = if (isUser) SocBorder else teamColor.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(12.dp)
                )
                .padding(12.dp)
        ) {
            Column {
                Text(
                    text = message.text,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )

                // Interactive Action Chip (If generated by AI)
                message.action?.let { action ->
                    Spacer(modifier = Modifier.height(10.dp))
                    InteractiveActionCard(
                        action = action,
                        executionResult = message.executionResult,
                        onExecute = { onExecuteAction(action) }
                    )
                }
            }
        }
    }
}

@Composable
fun InteractiveActionCard(
    action: AiAction,
    executionResult: String?,
    onExecute: () -> Unit
) {
    val dangerColor = when (action.dangerLevel) {
        "HIGH" -> ThreatCrimson
        "MEDIUM" -> WarningAmber
        else -> NeonCyan
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(AbyssBlack)
            .border(1.dp, dangerColor, RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Bolt,
                    contentDescription = null,
                    tint = dangerColor,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = "ACTIONABLE INTENT DETECTED",
                    color = dangerColor,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    style = Typography.labelSmall
                )
            }
            Text(
                text = action.target,
                color = TextSecondary,
                fontSize = 9.sp,
                style = Typography.labelSmall
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (executionResult != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = EmeraldSafe,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = executionResult,
                    color = EmeraldSafe,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        } else {
            Button(
                onClick = onExecute,
                colors = ButtonDefaults.buttonColors(
                    containerColor = dangerColor,
                    contentColor = TextPrimary
                ),
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(vertical = 6.dp)
            ) {
                Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = action.label,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
