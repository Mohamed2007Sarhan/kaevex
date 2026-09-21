package com.kaevex.fireware

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import com.kaevex.fireware.data.local.SecurePreferences
import com.kaevex.fireware.ui.components.BiometricHelper
import com.kaevex.fireware.ui.navigation.KaevexApp
import com.kaevex.fireware.ui.theme.KaevexTheme

class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val prefs = SecurePreferences(this)
        if (prefs.biometricsEnabled && prefs.isAuthenticated) {
            BiometricHelper.authenticate(
                activity = this,
                title = "Kaevex SOC Commander",
                subtitle = "Biometric unlock to access endpoint defense center",
                onSuccess = {
                    // Authenticated
                },
                onError = {
                    // If error or cancelled, user can still proceed or retry
                }
            )
        }

        setContent {
            KaevexTheme {
                KaevexApp(activity = this)
            }
        }
    }
}