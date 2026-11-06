package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/** Material 3 Expressive with the colors of the wallpaper (Material You) and expressive motion. */
object ReplayTheme {
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Content(content: @Composable () -> Unit) {
        val context = LocalContext.current
        val colors = if (isSystemInDarkTheme()) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        MaterialExpressiveTheme(colorScheme = colors, motionScheme = MotionScheme.expressive(), content = content)
    }
}
