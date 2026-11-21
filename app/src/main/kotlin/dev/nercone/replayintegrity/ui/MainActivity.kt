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
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ShortNavigationBar
import androidx.compose.material3.ShortNavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarState
import androidx.compose.material3.WideNavigationRail
import androidx.compose.material3.WideNavigationRailItem
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
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
 * The application frame: the top bar, the navigation (a bar at the bottom of a narrow window, a
 * rail at the side of a wide one), and the screen of the destination. The frame also owns the
 * dialogs and sheets that any screen can open: the engine log and the restricted-root dialog.
 */
object ReplayApp {
    enum class Destination(val title: Int, val selectedIcon: ImageVector, val icon: ImageVector) {
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

    /** The window width from which the navigation is a rail at the side. */
    val RAIL_WIDTH = 600.dp

    @OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Content(model: AppViewModel) {
        val state by model.state.collectAsStateWithLifecycle()
        val settings by model.settings.collectAsStateWithLifecycle()
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

        NotificationRequest(state, settings, model)

        val window = LocalWindowInfo.current.containerSize
        val wide = with(LocalDensity.current) { window.width.toDp() } >= RAIL_WIDTH
        // Each route has its own top bar state, so that a screen always opens with the bar expanded.
        val barState = rememberSaveable(route, saver = TopAppBarState.Saver) { TopAppBarState(-Float.MAX_VALUE, 0f, 0f) }
        val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(barState)
        val enter = MaterialTheme.motionScheme.defaultEffectsSpec<Float>()
        val exit = MaterialTheme.motionScheme.fastEffectsSpec<Float>()

        Row(Modifier.fillMaxSize()) {
            if (wide) Rail(destination) { navigator.open(it, null) }
            Scaffold(
                modifier = Modifier.weight(1f).nestedScroll(scrollBehavior.nestedScrollConnection),
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                topBar = {
                    Column {
                        LargeFlexibleTopAppBar(
                            title = { Text(title(route)) },
                            subtitle = state.operation?.let { { Text(Labels.operation(it)) } },
                            navigationIcon = {
                                if (route.page != null) {
                                    IconButton(onClick = { page = null }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                                }
                            },
                            scrollBehavior = scrollBehavior,
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                                scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                            ),
                        )
                        if (state.operation != null) LinearWavyProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = Widgets.SCREEN_PADDING))
                    }
                },
                bottomBar = { if (!wide) Bar(destination) { navigator.open(it, null) } },
            ) { padding ->
                AnimatedContent(
                    targetState = route,
                    transitionSpec = { fadeIn(enter) togetherWith fadeOut(exit) },
                    modifier = Modifier.fillMaxSize().padding(padding),
                    label = "route",
                ) { shown ->
                    Box(Modifier.fillMaxSize()) {
                        when (shown.destination) {
                            Destination.HOME -> HomeScreen.Content(state, settings, model, navigator)
                            Destination.ATTESTATION -> AttestationScreen.Content(state, settings, model)
                            Destination.TARGETS -> TargetsScreen.Content(state, settings, model)
                            Destination.SETTINGS -> SettingsScreen.Content(state, settings, model, shown.page) { page = it }
                        }
                    }
                }
            }
        }

        if (state.logShown) Notices.Log(state.log) { model.showLog(false) }
        (state.outcome as? Outcome.Failed)?.takeIf { it.restricted }?.let {
            Restricted(it, onRecheck = { model.dismissOutcome(); model.recheck() }, onDismiss = model::dismissOutcome)
        }
    }

    @Composable
    fun title(route: Route): String = when {
        route.page != null -> stringResource(route.page.title)
        route.destination == Destination.HOME -> stringResource(R.string.app_name)
        else -> stringResource(route.destination.title)
    }

    @Composable
    fun Bar(destination: Destination, onNavigate: (Destination) -> Unit) {
        ShortNavigationBar {
            Destination.entries.forEach { entry ->
                val selected = destination == entry
                ShortNavigationBarItem(
                    selected = selected,
                    onClick = { onNavigate(entry) },
                    icon = { Icon(if (selected) entry.selectedIcon else entry.icon, null) },
                    label = { Text(stringResource(entry.title)) },
                )
            }
        }
    }

    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Rail(destination: Destination, onNavigate: (Destination) -> Unit) {
        WideNavigationRail(arrangement = Arrangement.Center) {
            Destination.entries.forEach { entry ->
                val selected = destination == entry
                WideNavigationRailItem(
                    railExpanded = false,
                    selected = selected,
                    onClick = { onNavigate(entry) },
                    icon = { Icon(if (selected) entry.selectedIcon else entry.icon, null) },
                    label = { Text(stringResource(entry.title)) },
                )
            }
        }
    }

    /**
     * Asks for the notification permission once, after the configuration is first applied:
     * notifications report failures of the runs after a boot and of the scheduled refreshes,
     * which only happen from then on.
     */
    @Composable
    fun NotificationRequest(state: UiState, settings: Settings.Values, model: AppViewModel) {
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
        val context = LocalContext.current
        val outcome = state.outcome
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

    /** Explains that the root manager restricts root, and how to grant it fully. */
    @Composable
    fun Restricted(failure: Outcome.Failed, onRecheck: () -> Unit, onDismiss: () -> Unit) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.restricted_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.restricted_text))
                    Text(failure.text, style = MaterialTheme.typography.bodySmall, color = Widgets.secondary)
                }
            },
            confirmButton = { TextButton(onClick = onRecheck) { Text(stringResource(R.string.check_again)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.dismiss)) } },
        )
    }
}
