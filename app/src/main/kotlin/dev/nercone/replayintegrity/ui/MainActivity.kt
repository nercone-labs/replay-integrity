package dev.nercone.replayintegrity.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ShortNavigationBar
import androidx.compose.material3.ShortNavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.nercone.replayintegrity.R

class MainActivity : ComponentActivity() {
    val model: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { ReplayTheme.Content { ReplayApp.Content(model) } }
    }
}

/** The application frame: top bar, navigation bar, and the screen of the destination. */
object ReplayApp {
    enum class Destination(val title: Int, val selectedIcon: ImageVector, val icon: ImageVector) {
        HOME(R.string.tab_home, Icons.Filled.Home, Icons.Outlined.Home),
        SETTINGS(R.string.tab_settings, Icons.Filled.Settings, Icons.Outlined.Settings),
    }

    @OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Content(model: AppViewModel) {
        val state by model.state.collectAsStateWithLifecycle()
        val settings by model.settings.collectAsStateWithLifecycle()
        var destination by rememberSaveable { mutableStateOf(Destination.HOME) }
        val context = LocalContext.current
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}

        // Once the configuration is applied, notifications matter: they report boot failures.
        LaunchedEffect(settings.applied) {
            if (settings.applied && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
        val enter = MaterialTheme.motionScheme.defaultEffectsSpec<Float>()
        val exit = MaterialTheme.motionScheme.fastEffectsSpec<Float>()
        Scaffold(
            modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
            topBar = {
                Column {
                    LargeFlexibleTopAppBar(
                        title = { Text(stringResource(if (destination == Destination.HOME) R.string.app_name else destination.title)) },
                        subtitle = state.operation?.let { { Text(operationText(it)) } },
                        scrollBehavior = scrollBehavior,
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainer,
                            scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                        ),
                    )
                    if (state.operation != null) LinearWavyProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = Widgets.SCREEN_PADDING))
                }
            },
            bottomBar = {
                ShortNavigationBar {
                    Destination.entries.forEach { entry ->
                        val selected = destination == entry
                        ShortNavigationBarItem(
                            selected = selected,
                            onClick = { destination = entry },
                            icon = { Icon(if (selected) entry.selectedIcon else entry.icon, null) },
                            label = { Text(stringResource(entry.title)) },
                        )
                    }
                }
            },
        ) { padding ->
            AnimatedContent(
                targetState = destination,
                transitionSpec = { fadeIn(enter) togetherWith fadeOut(exit) },
                modifier = Modifier.fillMaxSize().padding(padding),
                label = "destination",
            ) { shown ->
                Box(Modifier.fillMaxSize()) {
                    when (shown) {
                        Destination.HOME -> HomeScreen.Content(state, model)
                        Destination.SETTINGS -> SettingsScreen.Content(settings, model)
                    }
                }
            }
        }
    }

    @Composable
    fun operationText(operation: Operation): String = stringResource(
        when (operation) {
            Operation.CHECKING -> R.string.operation_checking
            Operation.REFRESHING -> R.string.operation_refreshing
            Operation.REPAIRING -> R.string.operation_repairing
            Operation.RESTARTING -> R.string.operation_restarting
        },
    )
}
