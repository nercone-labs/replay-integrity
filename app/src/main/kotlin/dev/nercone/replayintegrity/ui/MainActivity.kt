package dev.nercone.replayintegrity.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings

class MainActivity : ComponentActivity() {
    val model: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { ReplayTheme.Content { ReplayApp.Content(model) } }
    }
}

/**
 * The application: its destinations, where the user is, and what any screen can open (the engine
 * log and the restricted-root dialog), in the frame shared with TypeFace Droplet (`Frame`).
 */
object ReplayApp {
    enum class Destination(override val title: Int, override val selectedIcon: ImageVector, override val icon: ImageVector) : Frame.Destination {
        HOME(R.string.tab_home, Icons.Filled.Home, Icons.Outlined.Home),
        ATTESTATION(R.string.tab_attestation, Icons.Filled.VerifiedUser, Icons.Outlined.VerifiedUser),
        TARGETS(R.string.tab_targets, Icons.Filled.Apps, Icons.Outlined.Apps),
        SETTINGS(R.string.tab_settings, Icons.Filled.Settings, Icons.Outlined.Settings),
    }

    /** Where the user is: a destination, and the page of the settings when one is open. */
    data class Route(val destination: Destination, val page: SettingsScreen.Page?)

    /** Opens `destination`, at `page` when it is the settings. */
    fun interface Navigator {
        fun open(destination: Destination, page: SettingsScreen.Page?)
    }

    @Composable
    fun Content(model: AppViewModel) {
        val state by model.state.collectAsStateWithLifecycle()
        val settings by model.settings.collectAsStateWithLifecycle()
        val data = remember(state, settings) { ScreenData(state, settings) }
        var destination by rememberSaveable { mutableStateOf(Destination.HOME) }
        var page by rememberSaveable { mutableStateOf<SettingsScreen.Page?>(null) }
        val route = Route(destination, page.takeIf { destination == Destination.SETTINGS })
        // Choosing a destination opens it at its start (the list of the settings, also when it
        // is chosen again from one of its pages); a shortcut may open a page of the settings.
        val navigator = Navigator { target, targetPage ->
            page = targetPage.takeIf { target == Destination.SETTINGS }
            destination = target
        }
        // Back leaves a page of the settings first, then returns to the home screen, and only
        // from there leaves the application.
        BackHandler(enabled = route.page != null) { page = null }
        BackHandler(enabled = route.page == null && destination != Destination.HOME) { navigator.open(Destination.HOME, null) }

        NotificationRequest(data, model)

        Frame.Content(
            destinations = Destination.entries,
            destination = destination,
            route = route,
            title = title(route),
            operation = state.operation?.let { Labels.operation(it) },
            onNavigate = { navigator.open(it, null) },
            onBack = if (route.page != null) ({ page = null }) else null,
        ) { shown ->
            when (shown.destination) {
                Destination.HOME -> HomeScreen.Content(data, model, navigator)
                Destination.ATTESTATION -> AttestationScreen.Content(data, model)
                Destination.TARGETS -> TargetsScreen.Content(data, model)
                Destination.SETTINGS -> SettingsScreen.Content(data, model, shown.page) { page = it }
            }
        }

        if (state.logShown) Frame.Log(state.log) { model.showLog(false) }
        (state.outcome as? Outcome.Failed)?.takeIf { it.restricted }?.let {
            Frame.Restricted(it.text, onRecheck = { model.dismissOutcome(); model.recheck() }, onDismiss = model::dismissOutcome)
        }
    }

    @Composable
    fun title(route: Route): String = when {
        route.page != null -> stringResource(route.page.title)
        route.destination == Destination.HOME -> stringResource(R.string.app_name)
        else -> stringResource(route.destination.title)
    }

    /**
     * Asks for the notification permission once, after the configuration is first applied:
     * notifications report failures of the runs after a boot and of the scheduled refreshes,
     * which only happen from then on.
     */
    @Composable
    fun NotificationRequest(data: ScreenData, model: AppViewModel) {
        val settings = data.settings
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
        val context = LocalContext.current
        val outcome = data.state.outcome
        LaunchedEffect(outcome) {
            val applied = outcome is Outcome.Refreshed || outcome is Outcome.Repaired || outcome is Outcome.Installed
            if (applied && !settings.notificationsAsked && settings.notifyFailures &&
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                model.configure { it.copy(notificationsAsked = true) }
                notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }
}
