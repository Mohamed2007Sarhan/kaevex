package com.kaevex.fireware.ui.navigation

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.kaevex.fireware.ui.components.BiometricHelper
import com.kaevex.fireware.ui.components.ServerSwitcherSheet
import com.kaevex.fireware.ui.components.SocTopBar
import com.kaevex.fireware.ui.screens.aicopilot.AiCopilotScreen
import com.kaevex.fireware.ui.screens.bootaudit.BootAuditScreen
import com.kaevex.fireware.ui.screens.cluster.AddServerDialog
import com.kaevex.fireware.ui.screens.cluster.ClusterScreen
import com.kaevex.fireware.ui.screens.cve.CveScreen
import com.kaevex.fireware.ui.screens.dashboard.DashboardScreen
import com.kaevex.fireware.ui.screens.settings.SettingsScreen
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KaevexApp(
    activity: FragmentActivity
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: Screen.Dashboard.route

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // ViewModels
    val authViewModel: AuthViewModel = viewModel()
    val dashboardViewModel: DashboardViewModel = viewModel()
    val bootAuditViewModel: BootAuditViewModel = viewModel()
    val cveViewModel: CveViewModel = viewModel()
    val clusterViewModel: ServerClusterViewModel = viewModel()
    val aiCopilotViewModel: AiCopilotViewModel = viewModel()
    val settingsViewModel: SettingsViewModel = viewModel()

    val authState by authViewModel.uiState.collectAsState()
    val clusterState by clusterViewModel.uiState.collectAsState()
    val settingsState by settingsViewModel.uiState.collectAsState()

    if (!authState.isAuthenticated) {
        com.kaevex.fireware.ui.screens.auth.AuthScreen(
            viewModel = authViewModel,
            onAuthenticated = {}
        )
        return
    }

    var showServerSwitcher by remember { mutableStateOf(false) }
    var showAddServerDialog by remember { mutableStateOf(false) }
    var showPanicConfirmDialog by remember { mutableStateOf(false) }

    // Collect user messages from ViewModels to show Snackbars
    LaunchedEffect(Unit) {
        launch {
            dashboardViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
        launch {
            bootAuditViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
        launch {
            cveViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
        launch {
            clusterViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
        launch {
            aiCopilotViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
        launch {
            settingsViewModel.userMessage.collect { msg -> snackbarHostState.showSnackbar(msg) }
        }
    }

    Scaffold(
        containerColor = AbyssBlack,
        snackbarHost = {
            SnackbarHost(hostState = snackbarHostState) { data ->
                Snackbar(
                    snackbarData = data,
                    containerColor = SocSurfaceElevated,
                    contentColor = TextPrimary,
                    shape = RoundedCornerShape(8.dp)
                )
            }
        },
        topBar = {
            SocTopBar(
                activeServer = clusterState.activeServer,
                onServerBadgeClick = { showServerSwitcher = true },
                onPanicLockdownClick = { showPanicConfirmDialog = true },
                onSettingsClick = {
                    navController.navigate(Screen.Settings.route) {
                        launchSingleTop = true
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = SocSurface,
                tonalElevation = 0.dp,
                modifier = Modifier.border(0.5.dp, SocBorder, RoundedCornerShape(0.dp))
            ) {
                Screen.bottomNavItems.forEach { screen ->
                    val selected = currentRoute == screen.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = {
                            Icon(
                                imageVector = screen.icon,
                                contentDescription = screen.title,
                                tint = if (selected) NeonCyan else TextMuted
                            )
                        },
                        label = {
                            Text(
                                text = screen.title,
                                color = if (selected) NeonCyan else TextMuted,
                                fontSize = 10.sp,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                style = Typography.labelSmall
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = NeonCyan.copy(alpha = 0.15f)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Dashboard.route) {
                DashboardScreen(
                    viewModel = dashboardViewModel,
                    onNavigateToBootAudit = {
                        navController.navigate(Screen.BootAudit.route) {
                            launchSingleTop = true
                        }
                    }
                )
            }
            composable(Screen.BootAudit.route) {
                BootAuditScreen(viewModel = bootAuditViewModel)
            }
            composable(Screen.CveHub.route) {
                CveScreen(viewModel = cveViewModel)
            }
            composable(Screen.Cluster.route) {
                ClusterScreen(viewModel = clusterViewModel)
            }
            composable(Screen.AiCopilot.route) {
                AiCopilotScreen(viewModel = aiCopilotViewModel)
            }
            composable(Screen.Settings.route) {
                SettingsScreen(
                    viewModel = settingsViewModel,
                    onSignOut = { authViewModel.signOut() }
                )
            }
        }
    }

    // Modal Server Switcher Sheet
    if (showServerSwitcher) {
        ServerSwitcherSheet(
            servers = clusterState.servers,
            activeServer = clusterState.activeServer,
            onSelectServer = { server ->
                clusterViewModel.selectServer(server)
                dashboardViewModel.refresh()
            },
            onAddNewServerClick = { showAddServerDialog = true },
            onDismiss = { showServerSwitcher = false }
        )
    }

    // Add Server Dialog
    if (showAddServerDialog) {
        AddServerDialog(
            onDismiss = { showAddServerDialog = false },
            onPair = { ip, port, pin, name, role ->
                clusterViewModel.addServer(ip, port, pin, name, role)
                dashboardViewModel.refresh()
            }
        )
    }

    // Panic Lockdown Confirmation Dialog with Biometrics
    if (showPanicConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showPanicConfirmDialog = false },
            containerColor = SocSurface,
            title = {
                Text(
                    text = "EMERGENCY CLUSTER LOCKDOWN",
                    color = ThreatCrimson,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(
                    text = "This will immediately isolate the host Windows network via the Windows Filtering Platform driver, sever all external sockets, and enforce firewall drop rules. Are you sure?",
                    color = TextPrimary,
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showPanicConfirmDialog = false
                        if (settingsState.biometricsEnabled) {
                            BiometricHelper.authenticate(
                                activity = activity,
                                title = "Confirm Emergency Lockdown",
                                subtitle = "Biometric authentication required to isolate cluster",
                                onSuccess = {
                                    dashboardViewModel.toggleFirewallLockdown()
                                },
                                onError = { err ->
                                    scope.launch { snackbarHostState.showSnackbar("Biometric authorization failed: $err") }
                                }
                            )
                        } else {
                            dashboardViewModel.toggleFirewallLockdown()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = ThreatCrimson,
                        contentColor = TextPrimary
                    )
                ) {
                    Text("ENGAGE LOCKDOWN", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showPanicConfirmDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            }
        )
    }
}
