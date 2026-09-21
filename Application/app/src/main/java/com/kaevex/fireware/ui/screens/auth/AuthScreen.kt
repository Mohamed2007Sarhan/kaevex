package com.kaevex.fireware.ui.screens.auth

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kaevex.fireware.R
import com.kaevex.fireware.ui.theme.*
import com.kaevex.fireware.ui.viewmodel.AuthViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(
    viewModel: AuthViewModel,
    onAuthenticated: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    val focusManager = LocalFocusManager.current
    val scrollState = rememberScrollState()

    var passwordVisible by remember { mutableStateOf(false) }
    var roleDropdownExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(state.isAuthenticated) {
        if (state.isAuthenticated) {
            onAuthenticated()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(AbyssBlack)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // Official Kaevex Logo & Icon
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(96.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(NeonCyan.copy(alpha = 0.25f), Color.Transparent)
                        )
                    )
                    .border(2.dp, NeonCyan, CircleShape)
                    .padding(8.dp)
            ) {
                Image(
                    painter = painterResource(id = R.drawable.kaevex_icon),
                    contentDescription = "Kaevex SOC Icon",
                    modifier = Modifier
                        .fillMaxSize()
                        .clip(CircleShape)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // App Title & Tagline
            Text(
                text = "KAEVEX MOBILE SOC",
                color = TextPrimary,
                fontSize = 22.sp,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 2.sp,
                fontFamily = FontFamily.Monospace
            )

            Text(
                text = "Endpoint Defense Commander & Remote Controller",
                color = NeonCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.5.sp,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Supabase Cloud Link Status Pill
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .background(SocSurfaceElevated)
                    .border(0.5.dp, SocBorder, RoundedCornerShape(12.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .clip(CircleShape)
                        .background(CleanEmerald)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "SUPABASE CLOUD AUTH LINKED",
                    color = TextMuted,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Tab Selector: Login vs Sign Up
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(SocSurface)
                    .border(1.dp, SocBorder, RoundedCornerShape(8.dp))
                    .padding(4.dp)
            ) {
                // Sign In Tab
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (!state.isSignUpMode) NeonCyan.copy(alpha = 0.15f) else Color.Transparent)
                        .border(
                            width = if (!state.isSignUpMode) 1.dp else 0.dp,
                            color = if (!state.isSignUpMode) NeonCyan else Color.Transparent,
                            shape = RoundedCornerShape(6.dp)
                        )
                        .clickable { if (state.isSignUpMode) viewModel.toggleAuthMode() }
                        .padding(vertical = 10.dp)
                ) {
                    Text(
                        text = "OPERATOR SIGN IN",
                        color = if (!state.isSignUpMode) NeonCyan else TextMuted,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }

                // Sign Up Tab
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (state.isSignUpMode) NeonCyan.copy(alpha = 0.15f) else Color.Transparent)
                        .border(
                            width = if (state.isSignUpMode) 1.dp else 0.dp,
                            color = if (state.isSignUpMode) NeonCyan else Color.Transparent,
                            shape = RoundedCornerShape(6.dp)
                        )
                        .clickable { if (!state.isSignUpMode) viewModel.toggleAuthMode() }
                        .padding(vertical = 10.dp)
                ) {
                    Text(
                        text = "NEW OPERATOR",
                        color = if (state.isSignUpMode) NeonCyan else TextMuted,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Error / Success Banners
            AnimatedVisibility(visible = state.errorMessage != null) {
                state.errorMessage?.let { msg ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(ThreatCrimson.copy(alpha = 0.15f))
                            .border(1.dp, ThreatCrimson.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                            .padding(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Error",
                            tint = ThreatCrimson,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = msg,
                            color = ThreatCrimson,
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }

            AnimatedVisibility(visible = state.successMessage != null) {
                state.successMessage?.let { msg ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(CleanEmerald.copy(alpha = 0.15f))
                            .border(1.dp, CleanEmerald.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                            .padding(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Success",
                            tint = CleanEmerald,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = msg,
                            color = CleanEmerald,
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }

            // Input: Email
            OutlinedTextField(
                value = state.email,
                onValueChange = { viewModel.onEmailChange(it) },
                label = { Text("Operator Email", fontSize = 12.sp) },
                placeholder = { Text("commander@kaevex.com", fontSize = 12.sp, color = TextMuted) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Email,
                        contentDescription = "Email",
                        tint = NeonCyan,
                        modifier = Modifier.size(18.dp)
                    )
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = if (state.isSignUpMode) ImeAction.Next else ImeAction.Done
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonCyan,
                    unfocusedBorderColor = SocBorder,
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    cursorColor = NeonCyan,
                    focusedLabelColor = NeonCyan,
                    unfocusedLabelColor = TextMuted
                ),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Input: Password
            OutlinedTextField(
                value = state.password,
                onValueChange = { viewModel.onPasswordChange(it) },
                label = { Text("Master Security Key / Password", fontSize = 12.sp) },
                placeholder = { Text("••••••••", fontSize = 12.sp, color = TextMuted) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = "Password",
                        tint = NeonCyan,
                        modifier = Modifier.size(18.dp)
                    )
                },
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            imageVector = if (passwordVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                            contentDescription = "Toggle Password",
                            tint = TextMuted,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                },
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = if (state.isSignUpMode) ImeAction.Next else ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = {
                        focusManager.clearFocus()
                        viewModel.authenticate()
                    }
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonCyan,
                    unfocusedBorderColor = SocBorder,
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    cursorColor = NeonCyan,
                    focusedLabelColor = NeonCyan,
                    unfocusedLabelColor = TextMuted
                ),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp)
            )

            // Extra Fields for Sign Up Mode
            if (state.isSignUpMode) {
                Spacer(modifier = Modifier.height(12.dp))

                // Input: Call-sign / Name
                OutlinedTextField(
                    value = state.callSign,
                    onValueChange = { viewModel.onCallSignChange(it) },
                    label = { Text("Operator Call-Sign / Name", fontSize = 12.sp) },
                    placeholder = { Text("Viper-1 (Alpha Commander)", fontSize = 12.sp, color = TextMuted) },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Badge,
                            contentDescription = "Call-Sign",
                            tint = CyberPurple,
                            modifier = Modifier.size(18.dp)
                        )
                    },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberPurple,
                        unfocusedBorderColor = SocBorder,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        cursorColor = CyberPurple,
                        focusedLabelColor = CyberPurple,
                        unfocusedLabelColor = TextMuted
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Dropdown: Operator Role
                ExposedDropdownMenuBox(
                    expanded = roleDropdownExpanded,
                    onExpandedChange = { roleDropdownExpanded = !roleDropdownExpanded },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    OutlinedTextField(
                        value = state.selectedRole,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Assigned Defense Role", fontSize = 12.sp) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = "Role",
                                tint = WarningAmber,
                                modifier = Modifier.size(18.dp)
                            )
                        },
                        trailingIcon = {
                            ExposedDropdownMenuDefaults.TrailingIcon(expanded = roleDropdownExpanded)
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = WarningAmber,
                            unfocusedBorderColor = SocBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedLabelColor = WarningAmber,
                            unfocusedLabelColor = TextMuted
                        ),
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp)
                    )

                    ExposedDropdownMenu(
                        expanded = roleDropdownExpanded,
                        onDismissRequest = { roleDropdownExpanded = false },
                        modifier = Modifier.background(SocSurfaceElevated)
                    ) {
                        viewModel.availableRoles.forEach { role ->
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = role,
                                        color = if (role == state.selectedRole) NeonCyan else TextPrimary,
                                        fontSize = 12.sp,
                                        fontWeight = if (role == state.selectedRole) FontWeight.Bold else FontWeight.Normal
                                    )
                                },
                                onClick = {
                                    viewModel.onRoleSelected(role)
                                    roleDropdownExpanded = false
                                }
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Primary Action Button: Authenticate / Initialize
            Button(
                onClick = {
                    focusManager.clearFocus()
                    viewModel.authenticate()
                },
                enabled = !state.isLoading,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NeonCyan,
                    contentColor = AbyssBlack,
                    disabledContainerColor = NeonCyan.copy(alpha = 0.4f)
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                if (state.isLoading) {
                    CircularProgressIndicator(
                        color = AbyssBlack,
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(20.dp)
                    )
                } else {
                    Icon(
                        imageVector = if (state.isSignUpMode) Icons.Default.PersonAdd else Icons.Default.LockOpen,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (state.isSignUpMode) "INITIALIZE OPERATOR CALL-SIGN" else "AUTHENTICATE SOC SESSION",
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        letterSpacing = 1.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Divider with OR
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                HorizontalDivider(modifier = Modifier.weight(1f), color = SocBorder)
                Text(
                    text = "  OR OFFLINE DIRECT ACCESS  ",
                    color = TextMuted,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace
                )
                HorizontalDivider(modifier = Modifier.weight(1f), color = SocBorder)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Guest SOC / Offline Bypass Card
            Card(
                colors = CardDefaults.cardColors(containerColor = SocSurface),
                border = androidx.compose.foundation.BorderStroke(1.dp, SocBorder),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.VpnLock,
                            contentDescription = "Bypass",
                            tint = WarningAmber,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "GUEST / DEMO SOC BYPASS",
                                color = TextPrimary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "Access mobile defense suite without cloud credentials",
                                color = TextSecondary,
                                fontSize = 10.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedButton(
                        onClick = { viewModel.bypassToDemo() },
                        border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber.copy(alpha = 0.8f)),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = WarningAmber
                        ),
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp)
                    ) {
                        Text(
                            text = "BYPASS: ENTER AS GUEST OPERATOR",
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Security Footer
            Text(
                text = "TOP SECRET // KAEVEX SOC ENCLAVE",
                color = TextMuted,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp
            )
            Text(
                text = "SUPABASE ENGINE ID: lqvijkatveozunxzlaid",
                color = TextMuted.copy(alpha = 0.6f),
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}
