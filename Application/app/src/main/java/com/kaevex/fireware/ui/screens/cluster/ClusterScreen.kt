package com.kaevex.fireware.ui.screens.cluster

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.data.model.ServerNode
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.ServerClusterViewModel

@Composable
fun ClusterScreen(
    viewModel: ServerClusterViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    var showPairDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(AbyssBlack)
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Section 1: Header with Add Server button
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "MULTI-SERVER CLUSTER MESH",
                        color = NeonCyan,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        style = Typography.labelSmall
                    )
                    Text(
                        text = "${state.servers.size} Connected Defense Nodes",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }

                Button(
                    onClick = { showPairDialog = true },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonCyan,
                        contentColor = AbyssBlack
                    ),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add Node", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Pair Node", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        // Real Local Host Auto-Discovery & Live Pings Bar
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { viewModel.startAutoDiscovery() },
                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(38.dp)
                ) {
                    if (state.isScanning) {
                        CircularProgressIndicator(color = NeonCyan, strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Scanning Subnet...", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    } else {
                        Icon(Icons.Default.Radar, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Auto-Discover Port 9009", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }

                OutlinedButton(
                    onClick = { viewModel.refreshLivePings() },
                    border = androidx.compose.foundation.BorderStroke(1.dp, EmeraldSafe),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldSafe),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.height(38.dp)
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Ping All", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        // Discovered Hosts List
        if (state.discoveredHosts.isNotEmpty()) {
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(SocSurfaceElevated)
                        .border(1.dp, NeonCyan.copy(alpha = 0.7f), RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = "DISCOVERED WINDOWS HOSTS ON LOCAL WI-FI",
                        color = NeonCyan,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    state.discoveredHosts.forEach { host ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("${host.ip}:${host.port}", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                Text("${host.pingMs}ms latency • Kaevex Service Found", color = EmeraldSafe, fontSize = 10.sp)
                            }
                            Button(
                                onClick = {
                                    viewModel.addServer(host.ip, host.port, "123456", "Discovered Host (${host.ip})", "Master")
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = AbyssBlack),
                                shape = RoundedCornerShape(6.dp),
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("Connect", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // Section 2: Cluster Broadcast Controls (Lockdown All & Audit All)
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = "CLUSTER BROADCAST CONTROLS",
                    color = TextPrimary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.5.sp
                )
                Text(
                    text = "Broadcast simultaneous commands to all linked Windows servers",
                    color = TextSecondary,
                    fontSize = 10.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = { viewModel.broadcastLockdownAll() },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ThreatCrimson.copy(alpha = 0.2f),
                            contentColor = ThreatCrimson
                        ),
                        border = androidx.compose.foundation.BorderStroke(1.dp, ThreatCrimson),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Lockdown All", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }

                    Button(
                        onClick = { viewModel.broadcastAuditAll() },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberPurple.copy(alpha = 0.2f),
                            contentColor = CyberPurple
                        ),
                        border = androidx.compose.foundation.BorderStroke(1.dp, CyberPurple),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Audit All Nodes", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Section 3: Server Nodes List
        item {
            Text(
                text = "MANAGED SERVERS",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                style = Typography.labelSmall
            )
        }

        items(state.servers) { server ->
            ServerNodeCard(
                server = server,
                isActive = server.id == state.activeServer?.id || (server.ip == state.activeServer?.ip && server.port == state.activeServer?.port),
                onSelect = { viewModel.selectServer(server) },
                onDelete = { viewModel.deleteServer(server) }
            )
        }
    }

    if (showPairDialog) {
        AddServerDialog(
            onDismiss = { showPairDialog = false },
            onPair = { ip, port, pin, name, role ->
                viewModel.addServer(ip, port, pin, name, role)
                showPairDialog = false
            }
        )
    }
}

@Composable
fun ServerNodeCard(
    server: ServerNode,
    isActive: Boolean,
    onSelect: () -> Unit,
    onDelete: () -> Unit
) {
    val statusColor = when (server.status) {
        "ONLINE" -> EmeraldSafe
        "ALERT" -> WarningAmber
        "ISOLATED" -> ThreatCrimson
        else -> TextSecondary
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (isActive) SocSurfaceElevated else SocSurface)
            .border(
                width = if (isActive) 1.5.dp else 1.dp,
                color = if (isActive) NeonCyan else SocBorder,
                shape = RoundedCornerShape(12.dp)
            )
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
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = server.name,
                    color = TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.width(6.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(CyberPurple.copy(alpha = 0.2f))
                        .border(0.5.dp, CyberPurple.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = server.role,
                        color = CyberPurple,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.SemiBold,
                        style = Typography.labelSmall
                    )
                }
            }

            if (isActive) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(NeonCyan.copy(alpha = 0.2f))
                        .border(1.dp, NeonCyan, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "ACTIVE TARGET",
                        color = NeonCyan,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        style = Typography.labelSmall
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "${server.ip}:${server.port}",
                color = TextSecondary,
                fontSize = 12.sp,
                style = Typography.labelMedium
            )
            Text(
                text = "Ping: ${server.pingMs}ms • Status: ${server.status}",
                color = statusColor,
                fontSize = 11.sp,
                style = Typography.labelSmall
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (!isActive) {
                TextButton(onClick = onSelect) {
                    Text("Set Active", color = NeonCyan, fontSize = 11.sp)
                }
            }
            IconButton(
                onClick = onDelete,
                modifier = Modifier.size(28.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.DeleteOutline,
                    contentDescription = "Remove Server",
                    tint = TextMuted,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Composable
fun AddServerDialog(
    onDismiss: () -> Unit,
    onPair: (ip: String, port: Int, pin: String, name: String, role: String) -> Unit
) {
    var ip by remember { mutableStateOf("192.168.1.") }
    var portText by remember { mutableStateOf("9009") }
    var pin by remember { mutableStateOf("849201") }
    var name by remember { mutableStateOf("") }
    var role by remember { mutableStateOf("Master") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SocSurface,
        title = {
            Text("Pair New Kaevex SOC Node", color = TextPrimary, fontSize = 16.sp, fontWeight = FontWeight.Bold)
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Enter target Windows Host IP, Port 9009, and 6-digit Pairing PIN:", color = TextSecondary, fontSize = 11.sp)

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Server Name (e.g. AWS Web Node)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NeonCyan,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    )
                )

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = ip,
                        onValueChange = { ip = it },
                        label = { Text("Host IP") },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = SocBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        )
                    )
                    OutlinedTextField(
                        value = portText,
                        onValueChange = { portText = it },
                        label = { Text("Port") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = SocBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        )
                    )
                }

                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text("6-Digit Pairing PIN") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = WarningAmber,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    )
                )

                OutlinedTextField(
                    value = role,
                    onValueChange = { role = it },
                    label = { Text("Role (Master / Web-Server / DB-Server)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberPurple,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    )
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val p = portText.toIntOrNull() ?: 9009
                    onPair(ip, p, pin, name, role)
                },
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = AbyssBlack)
            ) {
                Text("Pair & Connect", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = TextSecondary)
            }
        }
    )
}
