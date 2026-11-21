package dev.nercone.replayintegrity.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.engine.LogLevel
import dev.nercone.replayintegrity.engine.LogLine
import java.text.DateFormat
import java.util.Date

/**
 * The frame of the application and what any of its screens can open. It knows nothing of the
 * destinations of the application: each application lists its own (`Destination`) and draws the
 * screen of the route it is given.
 */
object Frame {
    /** A destination of the navigation: its name and its icons when chosen and when not. */
    interface Destination {
        val title: Int
        val selectedIcon: ImageVector
        val icon: ImageVector
    }

    /** The window width from which the navigation is a rail at the side instead of a bar at the bottom. */
    val RAIL_WIDTH = 600.dp

    /**
     * The frame: the top bar with `title` (and `operation`, with a progress indicator, while one
     * runs), the navigation between `destinations`, an optional floating action button, and the
     * screen of `route`, which `content` draws. `onBack` shows a way back in the top bar when it is
     * not `null`. Each route has its own state of the top bar, so that a screen always opens with
     * the bar expanded; `floatingButton` is told whether the bar is expanded, to shrink with it.
     */
    @OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun <D : Destination, T : Any> Content(
        destinations: List<D>,
        destination: D,
        route: T,
        title: String,
        operation: String?,
        onNavigate: (D) -> Unit,
        onBack: (() -> Unit)?,
        floatingButton: @Composable (expanded: Boolean) -> Unit = {},
        content: @Composable (T) -> Unit,
    ) {
        val window = LocalWindowInfo.current.containerSize
        val wide = with(LocalDensity.current) { window.width.toDp() } >= RAIL_WIDTH
        val barState = rememberSaveable(route, saver = TopAppBarState.Saver) { TopAppBarState(-Float.MAX_VALUE, 0f, 0f) }
        val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(barState)
        val enter = MaterialTheme.motionScheme.defaultEffectsSpec<Float>()
        val exit = MaterialTheme.motionScheme.fastEffectsSpec<Float>()

        Row(Modifier.fillMaxSize()) {
            if (wide) Rail(destinations, destination, onNavigate)
            Scaffold(
                modifier = Modifier.weight(1f).nestedScroll(scrollBehavior.nestedScrollConnection),
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                topBar = {
                    Column {
                        LargeFlexibleTopAppBar(
                            title = { Text(title) },
                            subtitle = operation?.let { { Text(it) } },
                            navigationIcon = {
                                if (onBack != null) IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                            },
                            scrollBehavior = scrollBehavior,
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                                scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                            ),
                        )
                        if (operation != null) LinearWavyProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = Widgets.SCREEN_PADDING))
                    }
                },
                bottomBar = { if (!wide) Bar(destinations, destination, onNavigate) },
                floatingActionButton = { floatingButton(scrollBehavior.state.collapsedFraction < 0.5f) },
            ) { padding ->
                AnimatedContent(
                    targetState = route,
                    transitionSpec = { fadeIn(enter) togetherWith fadeOut(exit) },
                    modifier = Modifier.fillMaxSize().padding(padding),
                    label = "route",
                ) { shown ->
                    Box(Modifier.fillMaxSize()) { content(shown) }
                }
            }
        }
    }

    @Composable
    fun <D : Destination> Bar(destinations: List<D>, destination: D, onNavigate: (D) -> Unit) {
        ShortNavigationBar {
            destinations.forEach { entry ->
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
    fun <D : Destination> Rail(destinations: List<D>, destination: D, onNavigate: (D) -> Unit) {
        WideNavigationRail(arrangement = Arrangement.Center) {
            destinations.forEach { entry ->
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

    /** Explains that the root manager restricts root, and how to grant it fully; `text` is the failure. */
    @Composable
    fun Restricted(text: String, onRecheck: () -> Unit, onDismiss: () -> Unit) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.restricted_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.restricted_text))
                    Text(text, style = MaterialTheme.typography.bodySmall, color = Widgets.secondary)
                }
            },
            confirmButton = { TextButton(onClick = onRecheck) { Text(stringResource(R.string.check_again)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.dismiss)) } },
        )
    }

    /** The engine log of the last operation, in a sheet, each line with its date and time. */
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun Log(lines: List<LogLine>, onDismiss: () -> Unit) {
        val format = remember { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM) }
        ModalBottomSheet(onDismissRequest = onDismiss, containerColor = MaterialTheme.colorScheme.surfaceContainer) {
            Text(stringResource(R.string.log), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
            if (lines.isEmpty()) Text(stringResource(R.string.log_empty), modifier = Modifier.padding(24.dp))
            LazyColumn(contentPadding = PaddingValues(start = 24.dp, end = 24.dp, bottom = 32.dp)) {
                items(lines) { line ->
                    Text(
                        "${format.format(Date(line.time * 1000))}  ${line.message}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = when (line.level) {
                            LogLevel.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
                            LogLevel.WARNING -> MaterialTheme.colorScheme.tertiary
                            LogLevel.ERROR -> MaterialTheme.colorScheme.error
                        },
                        modifier = Modifier.padding(vertical = 2.dp),
                    )
                }
            }
        }
    }
}
